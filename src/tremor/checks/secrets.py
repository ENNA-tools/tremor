"""Secret exposure checks — secrets in expressions and unsafe contexts."""

import re
from typing import Any

from tremor.checks.base import BaseCheck
from tremor.models import Finding, Severity, CheckID
from tremor.parsers import WorkflowFile

SECRET_IN_RUN = re.compile(r"\$\{\{\s*secrets\.\w+\s*\}\}")
SECRET_IN_ARGS = re.compile(r"secrets\.\w+")


class SecretExposureCheck(BaseCheck):
    id = "T006"
    name = "Secret in Unsafe Context"
    enabled_key = "secret_exposure"

    def run(self, workflow: WorkflowFile) -> list[Finding]:
        findings = []

        for job_name, step_idx, step in workflow.walk_steps():
            run_block = step.get("run", "")
            for match in SECRET_IN_RUN.finditer(run_block):
                secret_ref = match.group(0)

                if self._is_safe_usage(run_block, secret_ref):
                    continue

                lines = workflow.find_all_lines(re.escape(secret_ref.strip("${} ")))
                line = lines[0] if lines else 0

                findings.append(Finding(
                    check_id=CheckID.SECRET_IN_EXPRESSION,
                    severity=Severity.MEDIUM,
                    file=str(workflow.path),
                    line=line,
                    title=f"Secret directly interpolated in run block",
                    detail=(
                        f"Job '{job_name}' interpolates {secret_ref} directly in a shell script. "
                        "If the secret contains shell metacharacters, it could break the script "
                        "or leak via error messages and process listings."
                    ),
                    remediation=(
                        "Pass secrets through environment variables:\n"
                        "  env:\n"
                        f"    MY_SECRET: {secret_ref}\n"
                        '  run: echo "$MY_SECRET"'
                    ),
                    context=workflow.lines[line - 1].strip() if line else "",
                ))

        return findings

    def _is_safe_usage(self, run_block: str, secret_ref: str) -> bool:
        """Check if the secret is already assigned to an env var pattern."""
        clean = secret_ref.strip()
        lines = run_block.splitlines()
        for line in lines:
            stripped = line.strip()
            if clean in stripped and "=" in stripped:
                before_eq = stripped.split("=")[0].strip()
                if before_eq.isupper() or before_eq.startswith("export "):
                    return True
        return False
