from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from detecode.scoring.cvss_mapper import cwe_details


USER_INPUT = r"(\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b|req\.(query|body|params|cookies|headers)\b|request\.(query|body|params)\b)"


@dataclass(frozen=True)
class PatternRule:
    rule_id: str
    cwe: str
    languages: tuple[str, ...]
    regex: re.Pattern[str]
    message: str
    confidence: float = 0.82

    def applies_to(self, lang: str) -> bool:
        return lang in self.languages


RULES = [
    PatternRule(
        "php-sql-user-input",
        "CWE-89",
        ("php",),
        re.compile(r"(mysqli_query|mysql_query|pg_query|PDO::query|\->query)\s*\([^;\n]*" + USER_INPUT, re.I),
        "User input reaches SQL query construction. Use prepared statements/parameter binding.",
        0.93,
    ),
    PatternRule(
        "js-sql-user-input",
        "CWE-89",
        ("js",),
        re.compile(r"\b(db|connection|pool)\.(query|execute)\s*\([^;\n]*(\+|`|\$\{)[^;\n]*" + USER_INPUT, re.I),
        "User input appears concatenated into a SQL query. Use parameterized queries.",
        0.9,
    ),
    PatternRule(
        "php-xss-echo-input",
        "CWE-79",
        ("php",),
        re.compile(r"\b(echo|print|printf)\b[^;\n]*" + USER_INPUT, re.I),
        "Raw user input is rendered to the response. Encode with htmlspecialchars or a template escaper.",
        0.88,
    ),
    PatternRule(
        "js-xss-innerhtml",
        "CWE-79",
        ("js",),
        re.compile(r"\.(innerHTML|outerHTML)\s*=\s*[^;\n]*(location|document\.URL|document\.cookie|req\.|request\.)", re.I),
        "Untrusted data is assigned to HTML. Prefer textContent or sanitize first.",
        0.84,
    ),
    PatternRule(
        "php-command-injection",
        "CWE-78",
        ("php",),
        re.compile(r"\b(exec|shell_exec|system|passthru|popen|proc_open)\s*\([^;\n]*" + USER_INPUT, re.I),
        "User input reaches OS command execution. Avoid shell calls or strictly allowlist arguments.",
        0.94,
    ),
    PatternRule(
        "js-command-injection",
        "CWE-78",
        ("js",),
        re.compile(r"\b(exec|execSync|spawn|spawnSync)\s*\([^;\n]*" + USER_INPUT, re.I),
        "User input reaches child process execution. Avoid shell mode and validate arguments.",
        0.9,
    ),
    PatternRule(
        "php-path-traversal",
        "CWE-22",
        ("php",),
        re.compile(r"\b(file_get_contents|readfile|fopen|unlink|copy|rename)\s*\([^;\n]*" + USER_INPUT, re.I),
        "User input controls a filesystem path. Normalize and restrict to an allowlisted base directory.",
        0.85,
    ),
    PatternRule(
        "js-path-traversal",
        "CWE-22",
        ("js",),
        re.compile(r"\b(fs\.(readFile|readFileSync|createReadStream|unlink|writeFile|writeFileSync)|sendFile)\s*\([^;\n]*" + USER_INPUT, re.I),
        "User input controls a filesystem path. Normalize and restrict to an allowlisted base directory.",
        0.85,
    ),
    PatternRule(
        "php-eval-user-input",
        "CWE-94",
        ("php",),
        re.compile(r"\b(eval|assert)\s*\([^;\n]*" + USER_INPUT, re.I),
        "User input reaches dynamic code execution. Remove eval/assert for untrusted input.",
        0.96,
    ),
    PatternRule(
        "js-eval-user-input",
        "CWE-94",
        ("js",),
        re.compile(r"\b(eval|Function)\s*\([^;\n]*" + USER_INPUT, re.I),
        "User input reaches dynamic code execution. Avoid eval/Function for untrusted input.",
        0.94,
    ),
    PatternRule(
        "php-file-include-input",
        "CWE-98",
        ("php",),
        re.compile(r"\b(include|include_once|require|require_once)\b\s*\(?[^;\n]*" + USER_INPUT, re.I),
        "User input controls include/require target. Use static includes or strict allowlists.",
        0.93,
    ),
    PatternRule(
        "php-unrestricted-upload",
        "CWE-434",
        ("php",),
        re.compile(r"\bmove_uploaded_file\s*\([^;\n]*\$_FILES[^;\n]*(\$_(GET|POST|REQUEST)|\.[^;\n]*\$_FILES)", re.I),
        "Uploaded file path/name appears user-controlled. Enforce extension, MIME, and random server filename.",
        0.83,
    ),
    PatternRule(
        "php-insecure-deserialization",
        "CWE-502",
        ("php",),
        re.compile(r"\bunserialize\s*\([^;\n]*" + USER_INPUT, re.I),
        "Untrusted data reaches unserialize. Use JSON or allowed_classes=false with strict validation.",
        0.95,
    ),
    PatternRule(
        "js-insecure-deserialization",
        "CWE-502",
        ("js",),
        re.compile(r"\b(nodeSerialize|serialize|unserialize)\.unserialize\s*\([^;\n]*" + USER_INPUT, re.I),
        "Untrusted data reaches an unsafe deserializer. Use safe JSON parsing and schema validation.",
        0.9,
    ),
    PatternRule(
        "php-ssrf",
        "CWE-918",
        ("php",),
        re.compile(r"\b(curl_setopt|file_get_contents|fopen)\s*\([^;\n]*" + USER_INPUT, re.I),
        "User input controls an outbound URL. Validate scheme, host, and block internal networks.",
        0.76,
    ),
    PatternRule(
        "js-ssrf",
        "CWE-918",
        ("js",),
        re.compile(r"\b(fetch|axios\.get|axios\.post|request|get)\s*\([^;\n]*" + USER_INPUT, re.I),
        "User input controls an outbound request URL. Validate destination and block private networks.",
        0.76,
    ),
    PatternRule(
        "debug-info-exposure",
        "CWE-200",
        ("php", "js"),
        re.compile(r"\b(var_dump|print_r|console\.log)\s*\([^;\n]*(password|token|secret|api[_-]?key|cookie)", re.I),
        "Sensitive value appears logged or dumped. Remove secrets from debug output.",
        0.72,
    ),
]


def rule_metadata(rule_id: str) -> tuple[str, str, float, str] | None:
    for rule in RULES:
        if rule.rule_id == rule_id:
            name, cvss, severity = cwe_details(rule.cwe)
            return rule.cwe, name, cvss, severity
    return None


def language_for_path(path: str) -> str | None:
    suffix = Path(path).suffix.lower()
    if suffix in {".php", ".phtml"}:
        return "php"
    if suffix in {".js", ".jsx", ".mjs", ".cjs"}:
        return "js"
    return None
