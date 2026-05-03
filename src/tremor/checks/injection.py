"""Script injection detection — untrusted context in run blocks."""

import re
from typing import Any

from tremor.checks.base import BaseCheck
from tremor.models import Finding, Severity, CheckID
from tremor.parsers import WorkflowFile

INJECTABLE_CONTEXTS = [
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.head_commit.message",
    "github.event.head_commit.author.email",
    "github.event.head_commit.author.name",
    "github.event.commits[*].message",
    "github.event.commits[*].author.email",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.head_ref",
    "github.event.workflow_run.head_branch",
    "github.event.inputs.*",
]

INJECTION_PATTERN = re.compile(
    r"\$\{\{\s*("
    + "|".join(re.escape(c).replace(r"\*", r"[^}]*") for c in INJECTABLE_CONTEXTS)
    + r")\s*\}\}"
)


class ScriptInjectionCheck(BaseCheck):
    id = "T004"
    name = "Script Injection via Expression"
    enabled_key = "script_injection"

    def run(self, workflow: WorkflowFile) -> list[Finding]:
        findings = []

        for job_name, step_idx, step in workflow.walk_steps():
            run_block = step.get("run")
            if not run_block:
                continue

            for match in INJECTION_PATTERN.finditer(run_block):
                context_expr = match.group(0)
                injectable = match.group(1)

                lines = workflow.find_all_lines(re.escape(injectable))
                line = lines[0] if lines else 0

                findings.append(Finding(
                    check_id=CheckID.SCRIPT_INJECTION,
                    severity=Severity.CRITICAL,
                    file=str(workflow.path),
                    line=line,
                    title=f"Script injection: {injectable}",
                    detail=(
                        f"Job '{job_name}' interpolates untrusted context '{injectable}' "
                        "directly into a shell script. An attacker can craft a PR title, "
                        "commit message, or issue body containing shell metacharacters "
                        "to execute arbitrary commands."
                    ),
                    remediation=(
                        "Pass the value through an environment variable instead:\n"
                        f"  env:\n    UNTRUSTED: {context_expr}\n"
                        '  run: echo "$UNTRUSTED"'
                    ),
                    context=workflow.lines[line - 1].strip() if line else "",
                ))

        return findings
