"""Tests for runtime monitoring."""

import sys
import os
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from tremor.models import CheckID, Severity
from tremor.monitor import (
    NetworkConnection,
    NetworkSnapshot,
    ProcessInfo,
    ProcessSnapshot,
    EnvironmentSnapshot,
    RuntimeSnapshot,
    RuntimeMonitor,
    _normalize_command,
    _split_addr_port,
)


class TestSplitAddrPort:
    def test_ipv4(self):
        assert _split_addr_port("192.168.1.1:443") == ("192.168.1.1", 443)

    def test_ipv6(self):
        assert _split_addr_port("[::1]:8080") == ("::1", 8080)

    def test_wildcard(self):
        assert _split_addr_port("*:*") == ("*", 0)


class TestNormalizeCommand:
    def test_full_path(self):
        assert _normalize_command("/usr/bin/node --harmony index.js") == "node"

    def test_bare_command(self):
        assert _normalize_command("python3") == "python3"

    def test_empty(self):
        assert _normalize_command("") == ""


class TestEnvironmentSnapshot:
    def test_captures_env(self):
        snap = EnvironmentSnapshot.capture()
        assert isinstance(snap.visible, dict)
        assert isinstance(snap.redacted_keys, set)

    def test_redacts_secrets(self):
        os.environ["TREMOR_TEST_SECRET_KEY"] = "should-be-redacted"
        os.environ["TREMOR_TEST_VISIBLE"] = "visible"
        try:
            snap = EnvironmentSnapshot.capture()
            assert "TREMOR_TEST_SECRET_KEY" in snap.redacted_keys
            assert "TREMOR_TEST_SECRET_KEY" not in snap.visible
            assert "TREMOR_TEST_VISIBLE" in snap.visible
        finally:
            del os.environ["TREMOR_TEST_SECRET_KEY"]
            del os.environ["TREMOR_TEST_VISIBLE"]


class TestRuntimeMonitor:
    def test_compare_network_new_host(self):
        monitor = RuntimeMonitor()
        baseline_net = NetworkSnapshot(
            connections=[],
            hosts={"github.com": []},
        )
        current_net = NetworkSnapshot(
            connections=[],
            hosts={
                "github.com": [],
                "evil.com": [NetworkConnection(
                    protocol="tcp", local_addr="10.0.0.1", local_port=12345,
                    remote_addr="1.2.3.4", remote_port=443, state="ESTAB",
                    process="curl",
                )],
            },
        )
        baseline = RuntimeSnapshot(
            timestamp=0, network=baseline_net,
            processes=ProcessSnapshot(), environment=EnvironmentSnapshot(),
        )
        current = RuntimeSnapshot(
            timestamp=1, network=current_net,
            processes=ProcessSnapshot(), environment=EnvironmentSnapshot(),
        )
        findings = monitor.compare(baseline, current)
        assert len(findings) == 1
        assert findings[0].check_id == CheckID.NEW_NETWORK_HOST
        assert "evil.com" in findings[0].title

    def test_compare_processes_new_proc(self):
        monitor = RuntimeMonitor()
        baseline_procs = ProcessSnapshot(processes=[
            ProcessInfo(user="runner", pid=1, cpu_pct=0, mem_pct=0, vsz_kb=0, rss_kb=0, command="node"),
        ])
        current_procs = ProcessSnapshot(processes=[
            ProcessInfo(user="runner", pid=1, cpu_pct=0, mem_pct=0, vsz_kb=0, rss_kb=0, command="node"),
            ProcessInfo(user="runner", pid=2, cpu_pct=50, mem_pct=30, vsz_kb=0, rss_kb=0, command="/tmp/xmrig --donate=0"),
        ])
        baseline = RuntimeSnapshot(
            timestamp=0, network=NetworkSnapshot(),
            processes=baseline_procs, environment=EnvironmentSnapshot(),
        )
        current = RuntimeSnapshot(
            timestamp=1, network=NetworkSnapshot(),
            processes=current_procs, environment=EnvironmentSnapshot(),
        )
        findings = monitor.compare(baseline, current)
        suspicious = [f for f in findings if f.check_id == CheckID.SUSPICIOUS_PROCESS]
        assert len(suspicious) == 1
        assert "xmrig" in suspicious[0].title

    def test_compare_env_new_secret(self):
        monitor = RuntimeMonitor()
        baseline_env = EnvironmentSnapshot(
            visible={}, redacted_keys={"GITHUB_TOKEN"},
        )
        current_env = EnvironmentSnapshot(
            visible={}, redacted_keys={"GITHUB_TOKEN", "EXFIL_SECRET_KEY"},
        )
        baseline = RuntimeSnapshot(
            timestamp=0, network=NetworkSnapshot(),
            processes=ProcessSnapshot(), environment=baseline_env,
        )
        current = RuntimeSnapshot(
            timestamp=1, network=NetworkSnapshot(),
            processes=ProcessSnapshot(), environment=current_env,
        )
        findings = monitor.compare(baseline, current)
        secret_findings = [f for f in findings if f.check_id == CheckID.NEW_ENV_SECRET]
        assert len(secret_findings) == 1
        assert "EXFIL_SECRET_KEY" in secret_findings[0].title

    def test_no_findings_when_identical(self):
        monitor = RuntimeMonitor()
        snap = RuntimeSnapshot(
            timestamp=0,
            network=NetworkSnapshot(connections=[], hosts={"github.com": []}),
            processes=ProcessSnapshot(processes=[
                ProcessInfo(user="runner", pid=1, cpu_pct=0, mem_pct=0, vsz_kb=0, rss_kb=0, command="node"),
            ]),
            environment=EnvironmentSnapshot(visible={}, redacted_keys={"GITHUB_TOKEN"}),
        )
        findings = monitor.compare(snap, snap)
        assert len(findings) == 0
