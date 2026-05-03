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


def run_epicenter(target: str, threshold: int) -> None:
    from tremor.epicenter.engine import scan_path

    result = scan_path(target)

    overall_score = result.overall_score
    total = result.total_artifacts
    flagged = result.flagged_artifacts

    flat_findings = []
    for scan in result.scans:
        for f in scan.findings:
            flat_findings.append({
                "file": scan.path,
                "score": scan.anomaly_score,
                "type": f.finding_type.value,
                "confidence": f.confidence,
                "description": f.description,
                "location": f.location,
            })

    summary_parts = []
    if result.finding_summary:
        for ft, count in sorted(result.finding_summary.items(), key=lambda x: -x[1]):
            summary_parts.append(f"{ft}: {count}")
    summary_text = f"{flagged}/{total} artifacts flagged, score {overall_score:.0f}/100"
    if summary_parts:
        summary_text += f" ({', '.join(summary_parts[:5])})"

    for scan in result.scans:
        if not scan.findings:
            continue
        level = "error" if scan.anomaly_score >= 50 else "warning"
        for f in scan.findings:
            print(f"::{level} file={scan.path},title={f.finding_type.value}::{f.description}")

    output_file = os.environ.get("GITHUB_OUTPUT")
    if output_file:
        with open(output_file, "a") as f:
            f.write(f"findings={json.dumps(flat_findings)}\n")
            f.write(f"risk-score={overall_score:.0f}\n")
            f.write(f"epicenter-score={overall_score:.0f}\n")
            f.write(f"summary={summary_text}\n")

    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a") as f:
            f.write("## Tremor Epicenter\n\n")
            f.write(f"**Target:** `{target}` | **Score:** {overall_score:.0f}/100")
            f.write(f" (threshold: {threshold}) | **Artifacts:** {flagged}/{total} flagged\n\n")
            if flat_findings:
                f.write("| Score | File | Finding |\n")
                f.write("|---|---|---|\n")
                for scan in result.scans:
                    if scan.findings:
                        for sf in scan.findings:
                            f.write(f"| {scan.anomaly_score:.0f} | `{scan.path}` | [{sf.confidence:.0%}] {sf.description[:120]} |\n")
            else:
                f.write("No anomalies detected.\n")

    if flagged:
        print(f"\nTremor Epicenter: {summary_text}", file=sys.stderr)
    else:
        print(f"\nTremor Epicenter: Clean — {total} artifacts scanned, score {overall_score:.0f}/100")

    if overall_score >= threshold:
        sys.exit(2)


def main():
    mode = os.environ.get("TREMOR_MODE", "audit")
    severity = os.environ.get("TREMOR_SEVERITY", "medium")
    baseline_path = os.environ.get("TREMOR_BASELINE", ".tremor/baseline.json")
    config_path = os.environ.get("TREMOR_CONFIG", ".tremor/config.yml")
    base_ref = os.environ.get("TREMOR_BASE_REF", "origin/main")

    if mode == "epicenter":
        target = os.environ.get("TREMOR_TARGET", ".")
        threshold = int(os.environ.get("TREMOR_THRESHOLD", "25"))
        run_epicenter(target, threshold)
        return

    config = load_config(config_path)

    if mode == "diff":
        run_diff(config, base_ref)
        return

    if mode == "monitor":
        findings = run_monitor(config, baseline_path)
    elif mode == "audit":
        findings = run_audit(config)
    else:
        print(f"Unknown mode: {mode}. Use 'audit', 'monitor', 'diff', or 'epicenter'.", file=sys.stderr)
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
