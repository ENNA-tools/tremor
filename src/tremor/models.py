"""Core data models."""

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]

    def __ge__(self, other: "Severity") -> bool:
        return self.rank >= other.rank

    def __gt__(self, other: "Severity") -> bool:
        return self.rank > other.rank

    def __le__(self, other: "Severity") -> bool:
        return self.rank <= other.rank

    def __lt__(self, other: "Severity") -> bool:
        return self.rank < other.rank


class CheckID(Enum):
    UNPINNED_ACTION = "T001"
    MUTABLE_TAG = "T002"
    DANGEROUS_TRIGGER = "T003"
    SCRIPT_INJECTION = "T004"
    EXCESSIVE_PERMISSIONS = "T005"
    SECRET_IN_EXPRESSION = "T006"
    UNTRUSTED_PR_CHECKOUT = "T007"


@dataclass
class Finding:
    check_id: CheckID
    severity: Severity
    file: str
    line: int
    title: str
    detail: str
    remediation: str
    context: str = ""
    meta: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id.value,
            "severity": self.severity.value,
            "file": self.file,
            "line": self.line,
            "title": self.title,
            "detail": self.detail,
            "remediation": self.remediation,
            "context": self.context,
            "meta": self.meta,
        }
