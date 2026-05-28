from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class Finding:
    file: str
    line: int
    column: int
    cwe: str
    name: str
    cvss: float
    severity: str
    snippet: str
    message: str
    engine: str
    confidence: float

    def key(self) -> tuple[str, int, str]:
        return (self.file, self.line, self.cwe)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
