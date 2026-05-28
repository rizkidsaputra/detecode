from pathlib import Path

from detecode.scanner.aggregator import aggregate_findings
from detecode.scanner.ai_scanner import AIScanner
from detecode.scanner.local_scanner import LocalPatternScanner


SAMPLES = Path(__file__).parent / "samples"


def test_local_scanner_finds_php_and_js_vulnerabilities():
    findings = LocalPatternScanner().scan(SAMPLES)
    cwes = {finding.cwe for finding in findings}
    assert "CWE-89" in cwes
    assert "CWE-79" in cwes
    assert "CWE-78" in cwes
    assert "CWE-22" in cwes
    assert "CWE-94" in cwes


def test_ai_scanner_produces_semantic_findings():
    findings = AIScanner().scan(SAMPLES, threshold=0.68)
    assert findings
    assert any(finding.engine == "ai-semantic" for finding in findings)


def test_aggregation_deduplicates_same_file_line_cwe():
    findings = LocalPatternScanner().scan(SAMPLES) + AIScanner().scan(SAMPLES, threshold=0.68)
    merged = aggregate_findings(findings)
    keys = [finding.key() for finding in merged]
    assert len(keys) == len(set(keys))
