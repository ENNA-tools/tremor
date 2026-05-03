"""Trigger-based checks — dangerous events and untrusted PR checkouts."""

import re
from typing import Any

from tremor.checks.base import BaseCheck
from tremor.models import Finding, Severity, CheckID
from tremor.parsers import WorkflowFile

DANGEROUS_TRIGGERS = {
    "pull_request_target": (
        Severity.CRITICAL,
        "pull_request_target runs in the base repo context with access to secrets. "
        "Forked PRs can exploit this to exfiltrate credentials.",
    ),
    "workflow_run": (
        Severity.MEDIUM,
        "workflow_run can be triggered by forked PRs indirectly, potentially "
        "running privileged code based on untrusted input.",
    ),
    "issue_comment": (
        Severity.LOW,
        "issue_comment triggers can be abused if the workflow acts on comment "
        "content without validation.",
    ),
}


class DangerousTriggerCheck(BaseCheck):
    id = "T003"
    name = "Dangerous Workflow Trigger"
    enabled_key = "dangerous_triggers"

    def run(self, workflow: WorkflowFile) -> list[Finding]:
        findings = []
        allowed = set(self.config.get("allow", {}).get("triggers", []))
        triggers = workflow.triggers

        if triggers is None:
            return findings

        trigger_names = []
        if isinstance(triggers, str):
            trigger_names = [triggers]
        elif isinstance(triggers, list):
            trigger_names = triggers
        elif isinstance(triggers, dict):
            trigger_names = list(triggers.keys())

        for trigger in trigger_names:
            if trigger in allowed:
                continue
            if trigger not in DANGEROUS_TRIGGERS:
                continue

            severity, detail = DANGEROUS_TRIGGERS[trigger]
            line = workflow.find_line(rf"^\s*{re.escape(trigger)}\s*:")
            if not line:
                line = workflow.find_line(re.escape(trigger))

            findings.append(Finding(
                check_id=CheckID.DANGEROUS_TRIGGER,
                severity=severity,
                file=str(workflow.path),
                line=line,
                title=f"Dangerous trigger: {trigger}",
                detail=detail,
                remediation=(
                    f"If {trigger} is required, add environment and condition guards. "
                    "Minimize the secrets and permissions available to the triggered job."
                ),
                context=workflow.lines[line - 1].strip() if line else "",
            ))

        return findings


class UntrustedPRCheckoutCheck(BaseCheck):
    id = "T007"
    name = "Untrusted PR Head Checkout"
    enabled_key = "untrusted_pr_checkout"

    def run(self, workflow: WorkflowFile) -> list[Finding]:
        findings = []
        triggers = workflow.triggers

        if not isinstance(triggers, dict):
            return findings

        has_prt = "pull_request_target" in triggers

        if not has_prt:
            return findings

        for job_name, step_idx, step in workflow.walk_steps():
            uses = step.get("uses", "")
            if "actions/checkout" not in uses:
                continue

            with_block = step.get("with", {})
            ref = with_block.get("ref", "")

            pr_ref_patterns = [
                "github.event.pull_request.head.sha",
                "github.event.pull_request.head.ref",
                "github.head_ref",
            ]
            if any(p in str(ref) for p in pr_ref_patterns):
                line = workflow.find_line(re.escape(str(ref)))
                findings.append(Finding(
                    check_id=CheckID.UNTRUSTED_PR_CHECKOUT,
                    severity=Severity.CRITICAL,
                    file=str(workflow.path),
                    line=line,
                    title=f"pull_request_target checks out untrusted PR head",
                    detail=(
                        f"Job '{job_name}' uses pull_request_target and checks out the "
                        "PR head ref. This gives untrusted fork code access to repo secrets."
                    ),
                    remediation=(
                        "Never checkout the PR head in a pull_request_target workflow. "
                        "Use a two-workflow pattern: pull_request for untrusted code, "
                        "workflow_run for privileged operations."
                    ),
                    context=workflow.lines[line - 1].strip() if line else "",
                ))

        return findings
