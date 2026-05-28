from __future__ import annotations

from pathlib import Path
import re

from detecode.models import Finding
from detecode.scanner.patterns import RULES
from detecode.scoring.cvss_mapper import cwe_details
from detecode.utils.file_parser import detect_language, iter_source_files, safe_read


class LocalPatternScanner:
    """Small offline scanner used as a reliable fallback for demo and tests."""

    def scan(self, target: str | Path, lang: str = "auto") -> list[Finding]:
        findings: list[Finding] = []
        for path in iter_source_files(target, lang):
            detected = detect_language(path)
            if detected is None:
                continue
            findings.extend(self._scan_file(path, detected))
        return findings

    def _scan_file(self, path: Path, lang: str) -> list[Finding]:
        findings: list[Finding] = []
        lines = safe_read(path).splitlines()
        seen: set[tuple[int, str]] = set()
        for line_number, line in enumerate(lines, 1):
            for rule in RULES:
                if not rule.applies_to(lang):
                    continue
                match = rule.regex.search(line)
                if not match:
                    continue
                seen.add((line_number, rule.cwe))
                name, cvss, severity = cwe_details(rule.cwe)
                findings.append(
                    Finding(
                        file=str(path),
                        line=line_number,
                        column=max(match.start() + 1, 1),
                        cwe=rule.cwe,
                        name=name,
                        cvss=cvss,
                        severity=severity,
                        snippet=line.strip(),
                        message=rule.message,
                        engine="local-rules",
                        confidence=rule.confidence,
                    )
                )
        findings.extend(self._scan_tainted_dataflow(path, lang, lines, seen))
        return findings

    def _scan_tainted_dataflow(
        self,
        path: Path,
        lang: str,
        lines: list[str],
        seen: set[tuple[int, str]],
    ) -> list[Finding]:
        if lang == "php":
            return self._scan_php_tainted_dataflow(path, lines, seen)
        if lang == "js":
            return self._scan_js_tainted_dataflow(path, lines, seen)
        return []

    def _scan_php_tainted_dataflow(self, path: Path, lines: list[str], seen: set[tuple[int, str]]) -> list[Finding]:
        tainted: set[str] = set()
        findings: list[Finding] = []
        user_input = re.compile(r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b", re.I)
        assignment = re.compile(r"(?P<var>\$[A-Za-z_][A-Za-z0-9_]*)\s*(?:\.?=)\s*(?P<rhs>.+)")
        sanitizers = re.compile(
            r"\b(htmlspecialchars|htmlentities|mysqli_real_escape_string|pg_escape_string|intval|"
            r"basename|realpath|escapeshellarg|escapeshellcmd|filter_var|filter_input|"
            r"preg_replace\s*\(\s*['\"][^'\"]*\^[^'\"]*)\b",
            re.I,
        )

        sink_rules = [
            ("CWE-89", re.compile(r"\b(mysqli_query|mysql_query|pg_query|\->query|PDO::query)\b", re.I), "Tainted data reaches SQL execution. Use prepared statements/parameter binding."),
            ("CWE-79", re.compile(r"^\s*(echo|print|printf)\b", re.I), "Tainted data is rendered to the response. Encode with htmlspecialchars or a template escaper."),
            ("CWE-79", re.compile(r"\$(html|output|response|body|content|page)\b.*\.=", re.I), "Tainted data is appended to an HTML response buffer. Escape before rendering."),
            ("CWE-78", re.compile(r"\b(exec|shell_exec|system|passthru|popen|proc_open)\b", re.I), "Tainted data reaches OS command execution. Avoid shell calls or strictly allowlist arguments."),
            ("CWE-22", re.compile(r"\b(file_get_contents|readfile|fopen|unlink|copy|rename)\b", re.I), "Tainted data controls a filesystem path. Normalize and restrict to an allowlisted base directory."),
            ("CWE-94", re.compile(r"\b(eval|assert)\b", re.I), "Tainted data reaches dynamic code execution. Remove eval/assert for untrusted input."),
            ("CWE-98", re.compile(r"^\s*(include|include_once|require|require_once)\b", re.I), "Tainted data controls include/require target. Use static includes or strict allowlists."),
            ("CWE-434", re.compile(r"\b(move_uploaded_file)\b", re.I), "Uploaded file is accepted from user-controlled input. Validate extension, MIME, and store under a random server name."),
            ("CWE-502", re.compile(r"\bunserialize\b", re.I), "Tainted data reaches unserialize. Use JSON or allowed_classes=false with strict validation."),
            ("CWE-601", re.compile(r"\bheader\s*\(\s*['\"]Location\s*:", re.I), "Tainted data controls a redirect location. Restrict redirects to trusted destinations."),
            ("CWE-918", re.compile(r"\b(curl_setopt)\b", re.I), "Tainted data controls an outbound URL. Validate scheme, host, and block internal networks."),
        ]

        for line_number, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("//", "#", "*")):
                continue

            match = assignment.search(stripped)
            rhs_has_taint = bool(user_input.search(stripped) or any(var in stripped for var in tainted))
            if match:
                rhs = match.group("rhs")
                variable = match.group("var")
                if sanitizers.search(rhs):
                    tainted.discard(variable)
                elif self._is_output_buffer(variable):
                    # Output buffers collect tainted content but should not make
                    # every later static append look vulnerable.
                    pass
                elif user_input.search(rhs) or any(var in rhs for var in tainted):
                    tainted.add(variable)

            has_taint = user_input.search(stripped) or any(var in stripped for var in tainted)
            if not has_taint:
                continue

            for cwe, sink_regex, message in sink_rules:
                if (line_number, cwe) in seen or not sink_regex.search(stripped):
                    continue
                if cwe == "CWE-79" and ".=" in stripped and not self._html_append_has_tainted_rhs(stripped, tainted, user_input):
                    continue
                if cwe == "CWE-22" and re.search(r"\b(basename|realpath)\b", stripped, re.I):
                    continue
                findings.append(self._finding(path, line_number, cwe, stripped, message, 0.86))
                seen.add((line_number, cwe))

        return findings

    def _scan_js_tainted_dataflow(self, path: Path, lines: list[str], seen: set[tuple[int, str]]) -> list[Finding]:
        tainted: set[str] = set()
        findings: list[Finding] = []
        user_input = re.compile(r"\b(req\.(query|body|params|cookies|headers)|request\.(query|body|params)|location|document\.(URL|cookie|referrer))\b", re.I)
        assignment = re.compile(r"(?:const|let|var)?\s*(?P<var>[A-Za-z_$][A-Za-z0-9_$]*)\s*=\s*(?P<rhs>.+)")
        sink_rules = [
            ("CWE-89", re.compile(r"\b(db|connection|pool)\.(query|execute)\b", re.I), "Tainted data reaches SQL execution. Use parameterized queries."),
            ("CWE-79", re.compile(r"\.(innerHTML|outerHTML)\s*=|document\.write\b", re.I), "Tainted data is rendered as HTML. Prefer textContent or sanitize first."),
            ("CWE-78", re.compile(r"\b(exec|execSync|spawn|spawnSync)\b", re.I), "Tainted data reaches child process execution. Avoid shell mode and validate arguments."),
            ("CWE-22", re.compile(r"\b(fs\.(readFile|readFileSync|createReadStream|unlink|writeFile|writeFileSync)|sendFile)\b", re.I), "Tainted data controls a filesystem path. Normalize and restrict to an allowlisted base directory."),
            ("CWE-94", re.compile(r"\b(eval|Function)\b", re.I), "Tainted data reaches dynamic code execution. Avoid eval/Function for untrusted input."),
            ("CWE-918", re.compile(r"\b(fetch|axios\.(get|post)|request\s*\()\b", re.I), "Tainted data controls an outbound request URL. Validate destination and block private networks."),
        ]

        for line_number, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith(("//", "*")):
                continue
            match = assignment.search(stripped)
            if match:
                rhs = match.group("rhs")
                if user_input.search(rhs) or any(var in rhs for var in tainted):
                    tainted.add(match.group("var"))

            has_taint = user_input.search(stripped) or any(var in stripped for var in tainted)
            if not has_taint:
                continue
            for cwe, sink_regex, message in sink_rules:
                if (line_number, cwe) in seen or not sink_regex.search(stripped):
                    continue
                findings.append(self._finding(path, line_number, cwe, stripped, message, 0.86))
                seen.add((line_number, cwe))

        return findings

    def _finding(self, path: Path, line: int, cwe: str, snippet: str, message: str, confidence: float) -> Finding:
        name, cvss, severity = cwe_details(cwe)
        return Finding(
            file=str(path),
            line=line,
            column=1,
            cwe=cwe,
            name=name,
            cvss=cvss,
            severity=severity,
            snippet=snippet,
            message=message,
            engine="local-taint",
            confidence=confidence,
        )

    def _is_output_buffer(self, variable: str) -> bool:
        return variable.lower() in {"$html", "$output", "$response", "$body", "$content", "$page"}

    def _html_append_has_tainted_rhs(self, line: str, tainted: set[str], user_input: re.Pattern[str]) -> bool:
        if ".=" not in line:
            return False
        lhs, rhs = line.split(".=", 1)
        if not re.search(r"\$(html|output|response|body|content|page)\b", lhs, re.I):
            return False
        if "<" not in rhs and ">" not in rhs:
            return False
        return bool(user_input.search(rhs) or any(var in rhs for var in tainted))
