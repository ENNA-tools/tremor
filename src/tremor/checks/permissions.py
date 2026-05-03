"""Permission scope checks — overly broad GITHUB_TOKEN permissions."""

import re
from typing import Any

from tremor.checks.base import BaseCheck
from tremor.models import Finding, Severity, CheckID
from tremor.parsers import WorkflowFile

DANGEROUS_WRITE_SCOPES = {
    "contents": "Can push commits, create/delete branches and tags",
    "actions": "Can create/modify workflow files — self-modifying pipeline",
    "packages": "Can publish packages — supply chain vector",
    "deployments": "Can trigger deployments to production",
    "id-token": "Can mint OIDC tokens — cloud credential theft",
}


class ExcessivePermissionsCheck(BaseCheck):
    id = "T005"
    name = "Excessive Token Permissions"
    enabled_key = "excessive_permissions"

    def run(self, workflow: WorkflowFile) -> list[Finding]:
        findings = []
        allowed = set(self.config.get("allow", {}).get("permissions", []))

        perms = workflow.permissions
        if perms is None:
            line = workflow.find_line(r"^permissions\s*:") or 1
            findings.append(Finding(
                check_id=CheckID.EXCESSIVE_PERMISSIONS,
                severity=Severity.HIGH,
                file=str(workflow.path),
                line=line,
                title="No top-level permissions block — defaults to broad read-write",
                detail=(
                    "Without an explicit permissions block, the GITHUB_TOKEN gets the "
                    "repository's default permissions, which is often read-write for all scopes."
                ),
                remediation="Add a top-level `permissions: {}` block and grant only what's needed.",
            ))
            return findings

        if perms == "write-all":
            line = workflow.find_line(r"permissions\s*:\s*write-all")
            findings.append(Finding(
                check_id=CheckID.EXCESSIVE_PERMISSIONS,
                severity=Severity.CRITICAL,
                file=str(workflow.path),
                line=line or 1,
                title="Workflow grants write-all permissions",
                detail="Every scope is writable. A compromised step can modify code, packages, and deployments.",
                remediation="Replace with explicit per-scope permissions.",
            ))
            return findings

        if isinstance(perms, dict):
            for scope, level in perms.items():
                if scope in allowed:
                    continue
                if level != "write":
                    continue
                if scope not in DANGEROUS_WRITE_SCOPES:
                    continue

                line = workflow.find_line(rf"{re.escape(scope)}\s*:\s*write")
                findings.append(Finding(
                    check_id=CheckID.EXCESSIVE_PERMISSIONS,
                    severity=Severity.HIGH,
                    file=str(workflow.path),
                    line=line or 1,
                    title=f"Dangerous write scope: {scope}",
                    detail=DANGEROUS_WRITE_SCOPES[scope],
                    remediation=f"Verify '{scope}: write' is necessary. Scope it to the specific job that needs it.",
                ))

        for job_name, job in workflow.jobs.items():
            job_perms = job.get("permissions")
            if not isinstance(job_perms, dict):
                continue
            for scope, level in job_perms.items():
                if scope in allowed or level != "write" or scope not in DANGEROUS_WRITE_SCOPES:
                    continue
                line = workflow.find_line(rf"{re.escape(scope)}\s*:\s*write")
                findings.append(Finding(
                    check_id=CheckID.EXCESSIVE_PERMISSIONS,
                    severity=Severity.MEDIUM,
                    file=str(workflow.path),
                    line=line or 1,
                    title=f"Job '{job_name}' has dangerous write scope: {scope}",
                    detail=DANGEROUS_WRITE_SCOPES[scope],
                    remediation=f"Verify '{scope}: write' is necessary for job '{job_name}'.",
                ))

        return findings
