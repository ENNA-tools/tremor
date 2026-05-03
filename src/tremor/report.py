"""Report generation and GitHub Actions output integration."""

import json
import os
from typing import Any

from tremor.models import Finding, Severity


class Reporter:
    def __init__(self, severity_threshold: str = "medium"):
        self.threshold = Severity(severity_threshold)

    def build(self, findings: list[Finding]) -> dict[str, Any]:
        above_threshold = [f for f in findings if f.severity >= self.threshold]

        by_severity = {}
        for f in findings:
            by_severity.setdefault(f.severity.value, []).append(f.to_dict())

        risk_score = self._compute_risk(findings)

        total = len(findings)
        blocking = len(above_threshold)

        if blocking == 0:
            summary = f"Clean — {total} finding(s), none above {self.threshold.value} threshold"
            exit_code = 0
        else:
            summary = f"{blocking} finding(s) at or above {self.threshold.value} severity ({total} total)"
            exit_code = 1

        return {
            "findings": [f.to_dict() for f in findings],
            "by_severity": by_severity,
            "risk_score": risk_score,
            "summary": summary,
            "exit_code": exit_code,
            "total": total,
            "blocking": blocking,
            "threshold": self.threshold.value,
        }

    def set_outputs(self, report: dict[str, Any]):
        output_file = os.environ.get("GITHUB_OUTPUT")
        if not output_file:
            return

        with open(output_file, "a") as f:
            f.write(f"findings={json.dumps(report['findings'])}\n")
            f.write(f"risk-score={report['risk_score']}\n")
            f.write(f"summary={report['summary']}\n")

    def _compute_risk(self, findings: list[Finding]) -> int:
        if not findings:
            return 0
        weights = {"critical": 25, "high": 15, "medium": 8, "low": 3}
        score = sum(weights.get(f.severity.value, 0) for f in findings)
        return min(score, 100)


class GitHubAnnotator:
    def emit(self, report: dict[str, Any]):
        for finding in report["findings"]:
            level = "error" if Severity(finding["severity"]) >= Severity.HIGH else "warning"
            file = finding["file"]
            line = finding["line"]
            title = finding["title"]
            detail = finding["detail"]

            print(f"::{level} file={file},line={line},title={title}::{detail}")
