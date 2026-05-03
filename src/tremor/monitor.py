"""Runtime behavioral monitoring for GitHub Actions environments."""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time
from dataclasses import dataclass, field

from tremor.models import CheckID, Finding, Severity

_SECRET_PATTERN = re.compile(
    r"(SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL|PRIVATE)", re.IGNORECASE
)


@dataclass
class NetworkConnection:
    protocol: str
    local_addr: str
    local_port: int
    remote_addr: str
    remote_port: int
    state: str
    process: str
    remote_hostname: str = ""


@dataclass
class NetworkSnapshot:
    connections: list[NetworkConnection] = field(default_factory=list)
    hosts: dict[str, list[NetworkConnection]] = field(default_factory=dict)

    @classmethod
    def capture(cls) -> NetworkSnapshot:
        try:
            result = subprocess.run(
                ["ss", "-tunap"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return cls()

        connections = []
        for line in result.stdout.splitlines()[1:]:
            conn = _parse_ss_line(line)
            if conn:
                connections.append(conn)

        hosts: dict[str, list[NetworkConnection]] = {}
        for conn in connections:
            key = conn.remote_hostname or conn.remote_addr
            hosts.setdefault(key, []).append(conn)

        return cls(connections=connections, hosts=hosts)


def _parse_ss_line(line: str) -> NetworkConnection | None:
    parts = line.split()
    if len(parts) < 6:
        return None

    protocol = parts[0]
    state = parts[1]
    local_raw = parts[4]
    remote_raw = parts[5]
    process = parts[6] if len(parts) > 6 else ""

    local_addr, local_port = _split_addr_port(local_raw)
    remote_addr, remote_port = _split_addr_port(remote_raw)

    if remote_addr in ("0.0.0.0", "::", "*"):
        return None

    remote_hostname = ""
    try:
        remote_hostname = socket.getfqdn(remote_addr)
        if remote_hostname == remote_addr:
            remote_hostname = ""
    except (socket.herror, OSError):
        pass

    return NetworkConnection(
        protocol=protocol,
        local_addr=local_addr,
        local_port=local_port,
        remote_addr=remote_addr,
        remote_port=remote_port,
        state=state,
        process=process,
        remote_hostname=remote_hostname,
    )


def _split_addr_port(raw: str) -> tuple[str, int]:
    """Handle both IPv4 (addr:port) and IPv6 ([addr]:port or addr%scope:port)."""
    if raw.startswith("["):
        bracket_end = raw.rfind("]")
        addr = raw[1:bracket_end]
        port_str = raw[bracket_end + 2:]
    else:
        last_colon = raw.rfind(":")
        addr = raw[:last_colon]
        port_str = raw[last_colon + 1:]

    try:
        port = int(port_str)
    except ValueError:
        port = 0

    return addr, port


@dataclass
class ProcessInfo:
    user: str
    pid: int
    cpu_pct: float
    mem_pct: float
    vsz_kb: int
    rss_kb: int
    command: str


@dataclass
class ProcessSnapshot:
    processes: list[ProcessInfo] = field(default_factory=list)

    @classmethod
    def capture(cls) -> ProcessSnapshot:
        try:
            result = subprocess.run(
                ["ps", "aux", "--sort=-rss"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return cls()

        processes = []
        for line in result.stdout.splitlines()[1:]:
            proc = _parse_ps_line(line)
            if proc:
                processes.append(proc)

        return cls(processes=processes)

    @property
    def commands(self) -> set[str]:
        """Normalized command basenames for comparison."""
        return {_normalize_command(p.command) for p in self.processes}


def _parse_ps_line(line: str) -> ProcessInfo | None:
    parts = line.split(None, 10)
    if len(parts) < 11:
        return None

    try:
        return ProcessInfo(
            user=parts[0],
            pid=int(parts[1]),
            cpu_pct=float(parts[2]),
            mem_pct=float(parts[3]),
            vsz_kb=int(parts[4]),
            rss_kb=int(parts[5]),
            command=parts[10],
        )
    except (ValueError, IndexError):
        return None


def _normalize_command(cmd: str) -> str:
    """Extract the binary basename, stripping path and arguments."""
    executable = cmd.split()[0] if cmd else cmd
    return os.path.basename(executable)


@dataclass
class EnvironmentSnapshot:
    visible: dict[str, str] = field(default_factory=dict)
    redacted_keys: set[str] = field(default_factory=set)

    @classmethod
    def capture(cls) -> EnvironmentSnapshot:
        visible = {}
        redacted_keys: set[str] = set()

        for key, value in os.environ.items():
            if _SECRET_PATTERN.search(key):
                redacted_keys.add(key)
            else:
                visible[key] = value

        return cls(visible=visible, redacted_keys=redacted_keys)

    @property
    def all_keys(self) -> set[str]:
        return set(self.visible.keys()) | self.redacted_keys


@dataclass
class RuntimeSnapshot:
    timestamp: float
    network: NetworkSnapshot
    processes: ProcessSnapshot
    environment: EnvironmentSnapshot

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "network": {
                "connection_count": len(self.network.connections),
                "remote_hosts": list(self.network.hosts.keys()),
            },
            "processes": {
                "count": len(self.processes.processes),
                "commands": sorted(self.processes.commands),
            },
            "environment": {
                "visible_count": len(self.environment.visible),
                "redacted_count": len(self.environment.redacted_keys),
                "redacted_keys": sorted(self.environment.redacted_keys),
            },
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


class RuntimeMonitor:
    """Collects runtime snapshots and compares against baselines."""

    def collect(self) -> RuntimeSnapshot:
        return RuntimeSnapshot(
            timestamp=time.time(),
            network=NetworkSnapshot.capture(),
            processes=ProcessSnapshot.capture(),
            environment=EnvironmentSnapshot.capture(),
        )

    def compare(
        self, baseline: RuntimeSnapshot, current: RuntimeSnapshot
    ) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._compare_network(baseline.network, current.network))
        findings.extend(self._compare_processes(baseline.processes, current.processes))
        findings.extend(
            self._compare_environment(baseline.environment, current.environment)
        )
        return findings

    def _compare_network(
        self, baseline: NetworkSnapshot, current: NetworkSnapshot
    ) -> list[Finding]:
        findings = []
        baseline_hosts = set(baseline.hosts.keys())

        for host, connections in current.hosts.items():
            if host not in baseline_hosts:
                remote_ports = sorted({c.remote_port for c in connections})
                findings.append(
                    Finding(
                        check_id=CheckID.NEW_NETWORK_HOST,
                        severity=Severity.HIGH,
                        file="runtime",
                        line=0,
                        title=f"Connection to new host: {host}",
                        detail=(
                            f"Outbound connection to {host} on port(s) "
                            f"{remote_ports} not present in baseline."
                        ),
                        remediation=(
                            "Verify this host is expected for this workflow step. "
                            "If legitimate, add to the runtime baseline."
                        ),
                        meta={
                            "host": host,
                            "ports": remote_ports,
                            "connection_count": len(connections),
                        },
                    )
                )

        return findings

    def _compare_processes(
        self, baseline: ProcessSnapshot, current: ProcessSnapshot
    ) -> list[Finding]:
        findings = []
        baseline_commands = baseline.commands

        for proc in current.processes:
            normalized = _normalize_command(proc.command)
            if normalized not in baseline_commands:
                findings.append(
                    Finding(
                        check_id=CheckID.SUSPICIOUS_PROCESS,
                        severity=Severity.MEDIUM,
                        file="runtime",
                        line=0,
                        title=f"Unexpected process: {normalized}",
                        detail=(
                            f"Process '{proc.command}' (pid {proc.pid}, user "
                            f"{proc.user}) not found in baseline process list."
                        ),
                        remediation=(
                            "Investigate the process origin. If it is part of a "
                            "legitimate workflow step, add to the baseline allowlist."
                        ),
                        meta={
                            "pid": proc.pid,
                            "user": proc.user,
                            "command": proc.command,
                            "rss_kb": proc.rss_kb,
                            "cpu_pct": proc.cpu_pct,
                        },
                    )
                )

        return findings

    def _compare_environment(
        self, baseline: EnvironmentSnapshot, current: EnvironmentSnapshot
    ) -> list[Finding]:
        findings = []
        new_secrets = current.redacted_keys - baseline.redacted_keys

        for key in sorted(new_secrets):
            findings.append(
                Finding(
                    check_id=CheckID.NEW_ENV_SECRET,
                    severity=Severity.HIGH,
                    file="runtime",
                    line=0,
                    title=f"New secret-pattern environment variable: {key}",
                    detail=(
                        f"Environment variable '{key}' matches a secret pattern "
                        f"and was not present in the baseline snapshot."
                    ),
                    remediation=(
                        "Determine what injected this variable. A new secret "
                        "appearing mid-workflow may indicate exfiltration staging."
                    ),
                    meta={"variable": key},
                )
            )

        return findings
