#!/usr/bin/env python3
"""Tremor — Pipeline behavioral anomaly detection."""

import json
import os
import sys
from pathlib import Path

from tremor.config import load_config
from tremor.audit import WorkflowAuditor
from tremor.report import Reporter, GitHubAnnotator


def main():
    mode = os.environ.get("TREMOR_MODE", "audit")
    severity = os.environ.get("TREMOR_SEVERITY", "medium")
    baseline_path = os.environ.get("TREMOR_BASELINE", ".tremor/baseline.json")
    config_path = os.environ.get("TREMOR_CONFIG", ".tremor/config.yml")

    config = load_config(config_path)

    if mode == "audit":
        auditor = WorkflowAuditor(config)
        findings = auditor.run()
    else:
        print(f"Mode '{mode}' not yet implemented", file=sys.stderr)
        sys.exit(1)

    reporter = Reporter(severity_threshold=severity)
    report = reporter.build(findings)

    annotator = GitHubAnnotator()
    annotator.emit(report)

    reporter.set_outputs(report)

    if report["exit_code"] != 0:
        print(f"\nTremor: {report['summary']}", file=sys.stderr)
        sys.exit(report["exit_code"])

    print(f"\nTremor: {report['summary']}")


if __name__ == "__main__":
    main()
