from __future__ import annotations


CWE_CVSS = {
    "CWE-22": ("Path Traversal", 7.5),
    "CWE-78": ("OS Command Injection", 9.8),
    "CWE-79": ("Cross-Site Scripting", 6.1),
    "CWE-89": ("SQL Injection", 9.8),
    "CWE-94": ("Code Injection", 9.8),
    "CWE-98": ("PHP File Inclusion", 9.8),
    "CWE-200": ("Information Exposure", 5.3),
    "CWE-306": ("Missing Authentication", 9.8),
    "CWE-352": ("Cross-Site Request Forgery", 6.5),
    "CWE-434": ("Unrestricted File Upload", 9.8),
    "CWE-502": ("Insecure Deserialization", 9.8),
    "CWE-601": ("Open Redirect", 6.1),
    "CWE-918": ("Server-Side Request Forgery", 9.1),
}


def severity_from_cvss(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


def cwe_details(cwe: str) -> tuple[str, float, str]:
    name, score = CWE_CVSS.get(cwe, ("Unknown Weakness", 5.0))
    return name, score, severity_from_cvss(score)
