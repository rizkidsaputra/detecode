from __future__ import annotations

import math
import re
from pathlib import Path
from typing import Any

from detecode.models import Finding
from detecode.scanner.patterns import USER_INPUT
from detecode.scoring.cvss_mapper import cwe_details
from detecode.utils.file_parser import detect_language, iter_source_files, safe_read


class AIScanner:
    """AI-assisted semantic scanner.

    The default mode is a lightweight local model: it scores risky data-flow-like
    code windows with security features. If transformers are installed and
    enabled, this class can be extended to load a fine-tuned CodeBERT checkpoint.
    """

    RISKY_SINKS = {
        "CWE-89": r"((db|conn|connection|pool)\.(query|execute)|mysqli_query|mysql_query|pg_query|SELECT\s+.+FROM)",
        "CWE-79": r"(echo|print|innerHTML|outerHTML|document\.write)",
        "CWE-78": r"(exec|shell_exec|system|passthru|spawn|execSync)",
        "CWE-22": r"(file_get_contents|readfile|fopen|fs\.readFile|sendFile)",
        "CWE-94": r"(eval|Function|assert)",
        "CWE-98": r"(include|require|include_once|require_once)",
        "CWE-502": r"(unserialize|nodeSerialize)",
        "CWE-918": r"(curl_setopt|fetch|axios\.(get|post)|request\s*\()",
    }
    SECURITY_PREFILTER = re.compile(
        USER_INPUT
        + r"|(\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b)"
        + r"|\b(echo|print|printf|query|execute|mysqli_query|mysql_query|pg_query|eval|assert|exec|shell_exec|system|passthru|include|require|unserialize|readfile|file_get_contents|fopen|curl_setopt|fetch)\b"
        + r"|(\.innerHTML|\.outerHTML|document\.write|fs\.(readFile|readFileSync|createReadStream)|req\.(query|body|params|cookies|headers))",
        re.I,
    )

    def __init__(self, model_path: str | Path | None = None) -> None:
        self.model_path = Path(model_path) if model_path else None
        self.tokenizer: Any | None = None
        self.model: Any | None = None
        self.id2label: dict[int, str] = {}
        if self.model_path:
            self._load_transformer_model(self.model_path)

    def scan(self, target: str | Path, lang: str = "auto", threshold: float = 0.68) -> list[Finding]:
        findings: list[Finding] = []
        for path in iter_source_files(target, lang):
            detected = detect_language(path)
            if detected is None:
                continue
            findings.extend(self._scan_file(path, threshold))
        return findings

    def _scan_file(self, path: Path, threshold: float) -> list[Finding]:
        lines = safe_read(path).splitlines()
        findings: list[Finding] = []
        for line_number, line in enumerate(lines, 1):
            cwe, confidence = self._predict_line(line)
            if cwe is None or confidence < threshold:
                continue
            name, cvss, severity = cwe_details(cwe)
            findings.append(
                Finding(
                    file=str(path),
                    line=line_number,
                    column=1,
                    cwe=cwe,
                    name=name,
                    cvss=cvss,
                    severity=severity,
                    snippet=line.strip(),
                    message="AI semantic score indicates untrusted data may reach a sensitive sink.",
                    engine="ai-semantic",
                    confidence=confidence,
                )
            )
        return findings

    def _load_transformer_model(self, model_path: Path) -> None:
        try:
            from transformers import AutoModelForSequenceClassification, AutoTokenizer
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("Install transformers dan torch untuk memakai --model-path.") from exc

        self.tokenizer = AutoTokenizer.from_pretrained(str(model_path))
        self.model = AutoModelForSequenceClassification.from_pretrained(str(model_path))
        raw_id2label = getattr(self.model.config, "id2label", {})
        self.id2label = {int(key): value for key, value in raw_id2label.items()}
        self.model.eval()

    def _predict_line(self, line: str) -> tuple[str | None, float]:
        compact = line.strip()
        if not compact or compact.startswith(("//", "#", "*")):
            return None, 0.0

        if self.model is not None and self.tokenizer is not None:
            if not self.SECURITY_PREFILTER.search(compact):
                return None, 0.0
            return self._predict_with_transformer(compact)

        has_input = bool(re.search(USER_INPUT, compact, re.I))
        best_cwe: str | None = None
        best_score = 0.0

        for cwe, sink_regex in self.RISKY_SINKS.items():
            has_sink = bool(re.search(sink_regex, compact, re.I))
            if not has_sink:
                continue
            features = [
                1.0 if has_input else 0.0,
                0.8 if any(token in compact for token in ["+", ". $_", "${", "`"]) else 0.0,
                0.5 if len(compact) > 80 else 0.0,
                0.5 if re.search(r"(password|token|secret|cookie)", compact, re.I) else 0.0,
            ]
            raw = -1.2 + sum(features)
            score = 1.0 / (1.0 + math.exp(-raw))
            if has_input and score < 0.7:
                score = 0.7
            if score > best_score:
                best_cwe = cwe
                best_score = score

        return best_cwe, round(best_score, 2)

    def _predict_with_transformer(self, code: str) -> tuple[str | None, float]:
        import torch

        inputs = self.tokenizer(code, return_tensors="pt", truncation=True, max_length=256)
        with torch.no_grad():
            logits = self.model(**inputs).logits[0]
            probs = torch.softmax(logits, dim=-1)
            confidence, label_id = torch.max(probs, dim=-1)

        label = self.id2label.get(int(label_id), "safe")
        if label == "safe":
            return None, float(confidence)
        if not self._has_matching_security_evidence(code, label):
            return None, float(confidence)
        return label, round(float(confidence), 2)

    def _has_matching_security_evidence(self, code: str, cwe: str) -> bool:
        has_user_input = bool(re.search(USER_INPUT, code, re.I))
        has_browser_input = bool(re.search(r"\b(location|document\.(URL|cookie|referrer)|window\.name)\b", code, re.I))
        has_php_server_input = bool(re.search(r"\$_SERVER\s*\[\s*['\"](HTTP_|PHP_AUTH_|REQUEST_URI|QUERY_STRING)", code, re.I))
        has_source = has_user_input or has_browser_input or has_php_server_input

        checks = {
            "CWE-79": bool(re.search(r"\b(echo|print|printf)\b|\.innerHTML|\.outerHTML|document\.write", code, re.I)) and has_source,
            "CWE-89": bool(re.search(r"\b(mysqli_query|mysql_query|pg_query|query|execute)\b", code, re.I)) and has_source,
            "CWE-78": bool(re.search(r"\b(exec|shell_exec|system|passthru|spawn|execSync)\b", code, re.I)) and has_source,
            "CWE-22": bool(re.search(r"\b(file_get_contents|readfile|fopen|fs\.(readFile|readFileSync)|sendFile)\b", code, re.I)) and has_source,
            "CWE-94": bool(re.search(r"\b(eval|Function|assert)\b", code, re.I)) and has_source,
            "CWE-98": bool(re.search(r"\b(include|include_once|require|require_once)\b", code, re.I)) and has_source,
            "CWE-502": bool(re.search(r"\bunserialize\b|\.unserialize\b", code, re.I)) and has_source,
            "CWE-918": bool(re.search(r"\b(curl_setopt|fetch|axios\.(get|post)|request\s*\()", code, re.I)) and has_source,
        }
        return checks.get(cwe, False)