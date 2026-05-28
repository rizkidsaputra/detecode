from __future__ import annotations

from collections import defaultdict

from detecode.models import Finding


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def aggregate_findings(findings: list[Finding]) -> list[Finding]:
    grouped: dict[tuple[str, int, str], list[Finding]] = defaultdict(list)
    for finding in findings:
        grouped[finding.key()].append(finding)

    merged: list[Finding] = []
    for group in grouped.values():
        best = max(group, key=lambda item: (item.cvss, item.confidence))
        engines = sorted({item.engine for item in group})
        confidence = min(0.99, max(item.confidence for item in group) + 0.05 * (len(engines) - 1))
        merged.append(
            Finding(
                file=best.file,
                line=best.line,
                column=best.column,
                cwe=best.cwe,
                name=best.name,
                cvss=best.cvss,
                severity=best.severity,
                snippet=best.snippet,
                message=best.message,
                engine="+".join(engines),
                confidence=round(confidence, 2),
            )
        )

    return sorted(merged, key=lambda item: (SEVERITY_ORDER.get(item.severity, 9), item.file, item.line, item.cwe))
