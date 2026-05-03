"""Action pinning checks — unpinned refs and mutable tags."""

import re
from typing import Any

from tremor.checks.base import BaseCheck
from tremor.models import Finding, Severity, CheckID
from tremor.parsers import WorkflowFile

SHA_PATTERN = re.compile(r"@[0-9a-f]{40}$")
SEMVER_TAG = re.compile(r"@v?\d+(\.\d+){0,2}$")
MUTABLE_TAG = re.compile(r"@v?\d+$")


class UnpinnedActionCheck(BaseCheck):
    id = "T001"
    name = "Unpinned Action Reference"
    enabled_key = "unpinned_actions"

    def run(self, workflow: WorkflowFile) -> list[Finding]:
        findings = []
        allowed = set(self.config.get("allow", {}).get("actions", []))

        for job_name, step_idx, uses, step in workflow.walk_uses():
            if uses.startswith("./"):
                continue
            if any(uses.startswith(a) for a in allowed):
                continue
            if SHA_PATTERN.search(uses):
                continue

            line = workflow.find_line(re.escape(uses))
            findings.append(Finding(
                check_id=CheckID.UNPINNED_ACTION,
                severity=Severity.HIGH,
                file=str(workflow.path),
                line=line,
                title=f"Action not pinned to SHA: {uses}",
                detail=(
                    f"Job '{job_name}' uses '{uses}' without a full commit SHA. "
                    "A compromised tag can silently replace the action code."
                ),
                remediation=f"Pin to a specific commit SHA: {uses.split('@')[0]}@<commit-sha>",
                context=workflow.lines[line - 1].strip() if line else "",
            ))

        return findings


class MutableTagCheck(BaseCheck):
    id = "T002"
    name = "Mutable Major-Version Tag"
    enabled_key = "mutable_tags"

    def run(self, workflow: WorkflowFile) -> list[Finding]:
        findings = []
        allowed = set(self.config.get("allow", {}).get("actions", []))

        for job_name, step_idx, uses, step in workflow.walk_uses():
            if uses.startswith("./"):
                continue
            if any(uses.startswith(a) for a in allowed):
                continue
            if SHA_PATTERN.search(uses):
                continue
            if not MUTABLE_TAG.search(uses):
                continue

            line = workflow.find_line(re.escape(uses))
            findings.append(Finding(
                check_id=CheckID.MUTABLE_TAG,
                severity=Severity.MEDIUM,
                file=str(workflow.path),
                line=line,
                title=f"Mutable major-version tag: {uses}",
                detail=(
                    f"Job '{job_name}' uses '{uses}' — a major-version tag that the "
                    "maintainer can silently re-point to any commit."
                ),
                remediation=f"Pin to a full SHA or at minimum a specific release tag.",
                context=workflow.lines[line - 1].strip() if line else "",
            ))

        return findings
