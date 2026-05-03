"""Base check interface."""

from abc import ABC, abstractmethod
from typing import Any

from tremor.models import Finding
from tremor.parsers import WorkflowFile


class BaseCheck(ABC):
    """All checks implement this interface."""

    id: str
    name: str
    enabled_key: str

    def __init__(self, config: dict[str, Any]):
        self.config = config

    @property
    def enabled(self) -> bool:
        return self.config.get("checks", {}).get(self.enabled_key, True)

    @abstractmethod
    def run(self, workflow: WorkflowFile) -> list[Finding]:
        ...
