"""YAML workflow parsing with line number tracking."""

import re
from pathlib import Path
from typing import Any


class WorkflowFile:
    """Parsed GitHub Actions workflow with line-number-aware access."""

    def __init__(self, path: Path, raw: str, data: dict[str, Any]):
        self.path = path
        self.raw = raw
        self.lines = raw.splitlines()
        self.data = data

    @classmethod
    def from_path(cls, path: Path) -> "WorkflowFile":
        raw = path.read_text()
        try:
            import yaml
            data = yaml.safe_load(raw) or {}
        except Exception:
            data = {}
        return cls(path, raw, data)

    def find_line(self, pattern: str) -> int:
        """Return 1-indexed line number of first regex match, or 0."""
        regex = re.compile(pattern)
        for i, line in enumerate(self.lines):
            if regex.search(line):
                return i + 1
        return 0

    def find_all_lines(self, pattern: str) -> list[int]:
        """Return all 1-indexed line numbers matching pattern."""
        regex = re.compile(pattern)
        return [i + 1 for i, line in enumerate(self.lines) if regex.search(line)]

    @property
    def permissions(self) -> dict | str | None:
        return self.data.get("permissions")

    @property
    def triggers(self) -> dict | str | list | None:
        return self.data.get("on") or self.data.get(True)

    @property
    def jobs(self) -> dict[str, Any]:
        return self.data.get("jobs", {})

    def walk_steps(self):
        """Yield (job_name, step_index, step_dict) for every step."""
        for job_name, job in self.jobs.items():
            for i, step in enumerate(job.get("steps", [])):
                yield job_name, i, step

    def walk_uses(self):
        """Yield (job_name, step_index, uses_string, step_dict) for action references."""
        for job_name, i, step in self.walk_steps():
            if "uses" in step:
                yield job_name, i, step["uses"], step
