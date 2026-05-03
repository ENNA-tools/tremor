"""Workflow auditor — discovers and scans all workflow files."""

from pathlib import Path
from typing import Any

from tremor.checks import ALL_CHECKS
from tremor.models import Finding
from tremor.parsers import WorkflowFile


class WorkflowAuditor:
    def __init__(self, config: dict[str, Any]):
        self.config = config
        self.checks = [cls(config) for cls in ALL_CHECKS if cls(config).enabled]

    def discover_workflows(self) -> list[Path]:
        paths = []
        for workflow_dir in self.config.get("workflow_paths", [".github/workflows"]):
            d = Path(workflow_dir)
            if d.exists():
                paths.extend(sorted(d.glob("*.yml")))
                paths.extend(sorted(d.glob("*.yaml")))
        return paths

    def run(self) -> list[Finding]:
        findings = []
        for path in self.discover_workflows():
            try:
                workflow = WorkflowFile.from_path(path)
            except Exception as e:
                print(f"Warning: could not parse {path}: {e}")
                continue

            for check in self.checks:
                findings.extend(check.run(workflow))

        findings.sort(key=lambda f: (-f.severity.rank, f.file, f.line))
        return findings
