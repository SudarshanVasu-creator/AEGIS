"""AEGIS data models — Finding and Severity."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any


class Severity(enum.Enum):
    """Finding severity levels, ordered from highest to lowest."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        order = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]
        return order.index(self) > order.index(other)


@dataclass
class Finding:
    """A single security finding produced by an AEGIS scanner.

    Fields
    ------
    id          Unique string identifier for deduplication.
    severity    Severity enum value.
    file        Path of the affected file, relative to the scanned project root.
    line        Line number (1-based). None when a line number is not available.
    rule_id     Scanner rule identifier (e.g. "B602", "AEGIS-SECRET-AWS").
    title       Short human-readable title.
    description Detailed description of the issue.
    evidence    Raw matched snippet. INTERNAL USE ONLY — never written to output.
    redacted    Evidence with secret values replaced by [REDACTED].
                This is the value exported under the JSON key "evidence".
    remediation Actionable guidance for fixing the issue.
    """

    id: str
    severity: Severity
    file: str
    line: int | None
    rule_id: str
    title: str
    description: str
    evidence: str = field(default="", repr=False)
    redacted: str = field(default="")
    remediation: str = field(default="")

    def to_dict(self) -> dict[str, Any]:
        """Serialise the finding for JSON export.

        The internal ``evidence`` field is **excluded entirely**.
        The ``redacted`` value is exported under the key ``"evidence"``
        so reports remain actionable without exposing raw secret values.
        """
        return {
            "id": self.id,
            "severity": self.severity.value,
            "file": self.file,
            "line": self.line,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "evidence": self.redacted,
            "remediation": self.remediation,
        }
