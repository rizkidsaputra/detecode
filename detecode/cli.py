from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from detecode.models import Finding
from detecode.scanner.aggregator import aggregate_findings
from detecode.scanner.ai_scanner import AIScanner
from detecode.scanner.local_scanner import LocalPatternScanner
from detecode.scanner.semgrep_scanner import SemgrepScanner
from detecode.utils.file_parser import iter_source_files

try:
    from rich.console import Console
    from rich.table import Table
except ImportError:  # pragma: no cover
    Console = None
    Table = None


SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="detecode", description="AI-assisted PHP/JavaScript vulnerability scanner.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a PHP/JavaScript file or directory.")
    scan.add_argument("target", help="File or directory to scan.")
    scan.add_argument("--format", choices=["table", "json", "text"], default="table")
    scan.add_argument("--severity", choices=["critical", "high", "medium", "low", "info"], default=None)
    scan.add_argument("--lang", choices=["auto", "php", "js"], default="auto")
    scan.add_argument("--engine", choices=["hybrid", "semgrep", "ai", "local"], default="hybrid")
    scan.add_argument("--ai-threshold", type=float, default=0.68)
    scan.add_argument("--model-path", default=None, help="Optional local HuggingFace model directory for AI engine.")
    scan.add_argument("--exclude-path", action="append", default=[], help="Path substring or regex to exclude. Can be repeated.")
    scan.add_argument("--fail-on-findings", action="store_true", help="Return exit code 1 when vulnerabilities are found.")
    return parser


def run_scan(args: argparse.Namespace) -> int:
    target = Path(args.target)
    try:
        files_scanned = len(iter_source_files(target, args.lang))
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    findings: list[Finding] = []
    if args.engine == "local":
        findings.extend(LocalPatternScanner().scan(target, args.lang))
    elif args.engine in {"hybrid", "semgrep"}:
        findings.extend(SemgrepScanner(fallback=True).scan(target, args.lang))
    if args.engine in {"hybrid", "ai"}:
        findings.extend(AIScanner(args.model_path).scan(target, args.lang, args.ai_threshold))

    findings = aggregate_findings(findings)
    findings = filter_by_path(findings, args.exclude_path)
    findings = filter_by_severity(findings, args.severity)
    render(findings, args.format, str(target), files_scanned)
    return 1 if findings and args.fail_on_findings else 0


def filter_by_severity(findings: list[Finding], minimum: str | None) -> list[Finding]:
    if minimum is None:
        return findings
    max_rank = SEVERITY_RANK[minimum]
    return [finding for finding in findings if SEVERITY_RANK.get(finding.severity.lower(), 9) <= max_rank]


def filter_by_path(findings: list[Finding], exclude_patterns: list[str]) -> list[Finding]:
    if not exclude_patterns:
        return findings
    import re

    matchers = []
    for pattern in exclude_patterns:
        try:
            regex = re.compile(pattern, re.I)
            matchers.append(lambda value, regex=regex: bool(regex.search(value)))
        except re.error:
            plain = pattern.lower().strip("\"'")
            matchers.append(lambda value, plain=plain: plain in value.lower())
    return [finding for finding in findings if not any(matches(finding.file) for matches in matchers)]


def render(findings: list[Finding], fmt: str, target: str, files_scanned: int) -> None:
    if fmt == "json":
        print(json.dumps({"target": target, "files_scanned": files_scanned, "findings": [f.to_dict() for f in findings]}, indent=2))
        return
    if fmt == "text" or Console is None or Table is None:
        print(f"DeteCode - target={target} files={files_scanned} findings={len(findings)}")
        for idx, finding in enumerate(findings, 1):
            print(f"{idx}. {finding.file}:{finding.line} {finding.cwe} {finding.name} CVSS={finding.cvss} {finding.severity}")
            print(f"   {finding.snippet}")
            print(f"   {finding.message} [{finding.engine}, confidence={finding.confidence:.0%}]")
        return

    console = Console()
    console.print(f"[bold cyan]DeteCode[/bold cyan] target=[bold]{target}[/bold] files={files_scanned} findings={len(findings)}")
    table = Table(show_lines=False)
    table.add_column("#", justify="right", width=4)
    table.add_column("File")
    table.add_column("Line", justify="right", width=6)
    table.add_column("CWE")
    table.add_column("Vulnerability")
    table.add_column("CVSS", justify="right")
    table.add_column("Severity")
    table.add_column("Engine")
    for idx, finding in enumerate(findings, 1):
        table.add_row(
            str(idx),
            finding.file,
            str(finding.line),
            finding.cwe,
            finding.name,
            f"{finding.cvss:.1f}",
            finding.severity,
            finding.engine,
        )
    console.print(table)
    for idx, finding in enumerate(findings, 1):
        console.print(f"[bold]{idx}. {finding.file}:{finding.line}[/bold]")
        console.print(f"   {finding.snippet}")
        console.print(f"   {finding.message} confidence={finding.confidence:.0%}")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return run_scan(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
