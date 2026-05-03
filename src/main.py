#!/usr/bin/env python3
"""Tremor — Pipeline behavioral anomaly detection."""

import json
import os
import sys

from tremor.config import load_config
from tremor.audit import WorkflowAuditor
from tremor.baseline import BaselineStore
from tremor.diff import WorkflowDiffAnalyzer, format_pr_comment
from tremor.github_api import GitHubClient, GitHubAPIError, get_pr_number
from tremor.monitor import RuntimeMonitor
from tremor.report import Reporter, GitHubAnnotator


def run_audit(config: dict) -> list:
    auditor = WorkflowAuditor(config)
    return auditor.run()


def run_monitor(config: dict, baseline_path: str) -> list:
    store = BaselineStore()
    monitor = RuntimeMonitor()
    current = monitor.collect()

    snapshot_data = {
        "network_hosts": list(current.network.hosts.keys()),
        "process_commands": sorted(current.processes.commands),
        "env_secret_names": sorted(current.environment.redacted_keys),
    }

    existing = store.load(baseline_path)
    if existing is None:
        baseline = store.new_baseline(snapshot_data)
        store.save(baseline_path, baseline)
        print("Tremor: First run — baseline created, no comparison available.")
        return []

    store.save(baseline_path, store.merge(existing, snapshot_data))

    from tremor.models import Severity, CheckID, Finding

    aggregated = existing.get("aggregated", {})
    findings = []

    known_hosts = set(aggregated.get("known_hosts", []))
    current_hosts = set(current.network.hosts.keys())
    for host in sorted(current_hosts - known_hosts):
        conns = current.network.hosts[host]
        ports = sorted({c.remote_port for c in conns})
        findings.append(Finding(
            check_id=CheckID.NEW_NETWORK_HOST,
            severity=Severity.HIGH,
            file="runtime",
            line=0,
            title=f"Connection to new host: {host}",
            detail=f"Outbound connection to {host} on port(s) {ports} not in baseline.",
            remediation="Verify this host is expected. If legitimate, it will be added to the baseline.",
            meta={"host": host, "ports": ports},
        ))

    known_procs = set(aggregated.get("known_processes", []))
    current_procs = current.processes.commands
    for proc in sorted(current_procs - known_procs):
        findings.append(Finding(
            check_id=CheckID.SUSPICIOUS_PROCESS,
            severity=Severity.MEDIUM,
            file="runtime",
            line=0,
            title=f"Unexpected process: {proc}",
            detail=f"Process '{proc}' not found in baseline process list.",
            remediation="Investigate the process origin. If legitimate, it will be baselined.",
        ))

    known_secrets = set(aggregated.get("known_secrets", []))
    current_secrets = current.environment.redacted_keys
    for var in sorted(current_secrets - known_secrets):
        findings.append(Finding(
            check_id=CheckID.NEW_ENV_SECRET,
            severity=Severity.HIGH,
            file="runtime",
            line=0,
            title=f"New secret-pattern environment variable: {var}",
            detail=f"Environment variable '{var}' matches a secret pattern and was not in baseline.",
            remediation="Determine what injected this variable.",
        ))

    return findings


def run_diff(config: dict, base_ref: str) -> None:
    analyzer = WorkflowDiffAnalyzer(config, base_ref=base_ref)
    report = analyzer.analyze()

    summary_md = format_pr_comment(report)

    try:
        client = GitHubClient()
        client.write_step_summary(summary_md)

        pr_number = get_pr_number()
        if pr_number:
            client.post_or_update_comment(pr_number, summary_md)
            print(f"Tremor: Posted trust surface diff to PR #{pr_number}")
    except (RuntimeError, GitHubAPIError) as e:
        print(f"Tremor: Could not post to GitHub: {e}", file=sys.stderr)

    print(f"\nTremor: {report.summary}")

    if report.risk_delta >= 30:
        sys.exit(1)


def main():
    mode = os.environ.get("TREMOR_MODE", "audit")
    severity = os.environ.get("TREMOR_SEVERITY", "medium")
    baseline_path = os.environ.get("TREMOR_BASELINE", ".tremor/baseline.json")
    config_path = os.environ.get("TREMOR_CONFIG", ".tremor/config.yml")
    base_ref = os.environ.get("TREMOR_BASE_REF", "origin/main")

    config = load_config(config_path)

    if mode == "diff":
        run_diff(config, base_ref)
        return

    if mode == "monitor":
        findings = run_monitor(config, baseline_path)
    elif mode == "audit":
        findings = run_audit(config)
    else:
        print(f"Unknown mode: {mode}. Use 'audit', 'monitor', or 'diff'.", file=sys.stderr)
        sys.exit(1)

    if not findings:
        if mode == "monitor":
            return
        print("\nTremor: Clean — no findings.")
        return

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
