from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

from detecode.models import Finding
from detecode.scanner.local_scanner import LocalPatternScanner
from detecode.scoring.cvss_mapper import cwe_details


class SemgrepScanner:
    def __init__(self, rules_dir: str | Path | None = None, fallback: bool = True) -> None:
        self.rules_dir = Path(rules_dir) if rules_dir else Path(__file__).resolve().parents[1] / "rules"
        self.fallback = fallback

    def scan(self, target: str | Path, lang: str = "auto") -> list[Finding]:
        if shutil.which("semgrep") is None:
            if self.fallback:
                return LocalPatternScanner().scan(target, lang)
            return []

        configs = self._configs_for_lang(lang)
        command = [
            "semgrep",
            "scan",
            "--json",
            "--quiet",
            "--metrics=off",
            *sum([["--config", str(config)] for config in configs], []),
            str(target),
        ]
        try:
            completed = subprocess.run(command, capture_output=True, text=True, check=False, encoding="utf-8")
        except OSError:
            return LocalPatternScanner().scan(target, lang) if self.fallback else []

        if completed.returncode not in (0, 1):
            print(f"Semgrep gagal, memakai fallback scanner: {completed.stderr.strip()}", file=sys.stderr)
            return LocalPatternScanner().scan(target, lang) if self.fallback else []

        try:
            payload = json.loads(completed.stdout or "{}")
        except json.JSONDecodeError:
            return LocalPatternScanner().scan(target, lang) if self.fallback else []

        findings = [self._from_result(item) for item in payload.get("results", [])]
        return [finding for finding in findings if finding is not None]

    def _configs_for_lang(self, lang: str) -> list[Path]:
        if lang == "php":
            return [self.rules_dir / "php_rules.yaml"]
        if lang == "js":
            return [self.rules_dir / "js_rules.yaml"]
        return [self.rules_dir / "php_rules.yaml", self.rules_dir / "js_rules.yaml"]

    def _from_result(self, result: dict) -> Finding | None:
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})
        cwe = str(metadata.get("cwe", "CWE-200")).upper()
        name, cvss, severity = cwe_details(cwe)
        start = result.get("start", {})
        return Finding(
            file=str(Path(result.get("path", "")).resolve()),
            line=int(start.get("line", 1)),
            column=int(start.get("col", 1)),
            cwe=cwe,
            name=str(metadata.get("name") or name),
            cvss=cvss,
            severity=severity,
            snippet=str(extra.get("lines", "")).strip(),
            message=str(extra.get("message", "Potential vulnerability detected.")),
            engine="semgrep",
            confidence=float(metadata.get("confidence", 0.92)),
        )
