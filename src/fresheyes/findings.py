"""Findings and severities produced by a scan."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum

__all__ = ["Finding", "SEVERITY_ORDER", "Severity", "counts_by_severity"]


class Severity(str, Enum):
    """Severity of a finding, from least to most urgent."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        """Numeric rank used for threshold comparisons (higher is worse)."""
        return _RANK[self.value]

    @classmethod
    def parse(cls, value: str) -> Severity:
        """Parse a severity name, raising ``ValueError`` for unknown names."""
        if isinstance(value, str):
            try:
                return cls(value.strip().lower())
            except ValueError:
                pass
        valid = ", ".join(item.value for item in cls)
        raise ValueError(f"invalid severity {value!r}; expected one of: {valid}")

    def __str__(self) -> str:
        return self.value


_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

#: Severities ordered from most to least urgent, for display purposes.
SEVERITY_ORDER = (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)


@dataclass(frozen=True, slots=True)
class Finding:
    """A single problem reported by a rule."""

    path: str
    line: int
    col: int
    rule_id: str
    severity: Severity
    message: str
    fix: str

    @property
    def location(self) -> str:
        return f"{self.path}:{self.line}:{self.col}"

    @property
    def sort_key(self) -> tuple[str, int, int, str]:
        return (self.path, self.line, self.col, self.rule_id)

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "line": self.line,
            "col": self.col,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "fix": self.fix,
        }


def counts_by_severity(findings: Iterable[Finding]) -> dict[str, int]:
    """Count findings per severity, always reporting every severity key."""
    counts = {severity.value: 0 for severity in SEVERITY_ORDER}
    total = 0
    for finding in findings:
        counts[finding.severity.value] += 1
        total += 1
    counts["total"] = total
    return counts
