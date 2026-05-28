from __future__ import annotations

from pathlib import Path


SUPPORTED_EXTENSIONS = {
    ".php": "php",
    ".phtml": "php",
    ".js": "js",
    ".jsx": "js",
    ".mjs": "js",
    ".cjs": "js",
}

IGNORED_DIRS = {".git", "node_modules", "vendor", "__pycache__", ".venv", "venv"}


def detect_language(path: Path) -> str | None:
    return SUPPORTED_EXTENSIONS.get(path.suffix.lower())


def iter_source_files(target: str | Path, lang: str = "auto") -> list[Path]:
    root = Path(target).resolve()
    if not root.exists():
        raise FileNotFoundError(f"Target tidak ditemukan: {root}")

    files = [root] if root.is_file() else [
        path
        for path in root.rglob("*")
        if path.is_file() and not any(part in IGNORED_DIRS for part in path.parts)
    ]

    selected: list[Path] = []
    for path in files:
        detected = detect_language(path)
        if detected is None:
            continue
        if lang != "auto" and detected != lang:
            continue
        selected.append(path)
    return sorted(selected)


def safe_read(path: Path) -> str:
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return path.read_text(encoding=encoding)
        except UnicodeDecodeError:
            continue
    return path.read_text(errors="ignore")
