"""Baseline management for behavioral anomaly detection."""

import json
import math
import statistics
from datetime import datetime, timezone
from pathlib import Path

BASELINE_VERSION = 2
DEFAULT_WINDOW = 20
DEFAULT_PATH = ".tremor/baseline.json"


class BaselineStore:

    def load(self, path: str = DEFAULT_PATH) -> dict | None:
        p = Path(path)
        if not p.exists():
            return None
        with open(p) as f:
            return json.load(f)

    def save(self, path: str, data: dict) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w") as f:
            json.dump(data, f, indent=2)

    def merge(self, existing: dict, new: dict, window: int = DEFAULT_WINDOW) -> dict:
        now = datetime.now(timezone.utc).isoformat()

        snapshots = existing.get("snapshots", [])
        snapshots.append(new)
        snapshots = snapshots[-window:]

        aggregated = self._aggregate(snapshots)

        return {
            "version": BASELINE_VERSION,
            "created": existing.get("created", now),
            "updated": now,
            "snapshots": snapshots,
            "aggregated": aggregated,
        }

    def new_baseline(self, snapshot: dict) -> dict:
        now = datetime.now(timezone.utc).isoformat()
        return {
            "version": BASELINE_VERSION,
            "created": now,
            "updated": now,
            "snapshots": [snapshot],
            "aggregated": self._aggregate([snapshot]),
        }

    def _aggregate(self, snapshots: list[dict]) -> dict:
        known_hosts: set[str] = set()
        known_processes: set[str] = set()
        known_secrets: set[str] = set()
        timing_data: dict[str, list[float]] = {}

        for snap in snapshots:
            known_hosts.update(snap.get("network_hosts", []))
            known_processes.update(snap.get("process_commands", []))
            known_secrets.update(snap.get("env_secret_names", []))
            for step, duration in snap.get("step_durations", {}).items():
                timing_data.setdefault(step, []).append(duration)

        timing_stats = {}
        for step, durations in timing_data.items():
            n = len(durations)
            mean = statistics.mean(durations)
            stddev = statistics.stdev(durations) if n >= 2 else 0.0
            timing_stats[step] = {
                "mean": round(mean, 3),
                "stddev": round(stddev, 3),
                "samples": n,
            }

        return {
            "known_hosts": sorted(known_hosts),
            "known_processes": sorted(known_processes),
            "known_secrets": sorted(known_secrets),
            "timing_stats": timing_stats,
        }


class AnomalyDetector:

    def detect_new_hosts(
        self, baseline_hosts: set[str], current_hosts: set[str]
    ) -> list[str]:
        return sorted(current_hosts - baseline_hosts)

    def detect_new_processes(
        self, baseline_procs: set[str], current_procs: set[str]
    ) -> list[str]:
        return sorted(current_procs - baseline_procs)

    def detect_timing_anomaly(
        self,
        baseline_durations: list[float],
        current_duration: float,
        z_threshold: float = 2.5,
    ) -> bool:
        if len(baseline_durations) < 2:
            return False

        mean = statistics.mean(baseline_durations)
        stddev = statistics.stdev(baseline_durations)

        if stddev == 0.0:
            return current_duration != mean

        z_score = abs(current_duration - mean) / stddev
        return z_score > z_threshold

    def detect_new_secrets(
        self, baseline_vars: set[str], current_vars: set[str]
    ) -> list[str]:
        return sorted(current_vars - baseline_vars)


class ArtifactManager:
    """Baseline persistence via GitHub Actions artifacts.

    TODO: Implement artifact upload/download using ACTIONS_RUNTIME_TOKEN
    and ACTIONS_RUNTIME_URL for cross-run persistence. For v0.2, baselines
    are stored in-repo at .tremor/baseline.json and persist via git or
    actions/cache.
    """

    def upload(self, path: str, artifact_name: str = "tremor-baseline") -> None:
        raise NotImplementedError(
            "Artifact upload not yet implemented. "
            "Use file-based storage with actions/cache for now."
        )

    def download(self, artifact_name: str, path: str) -> bool:
        raise NotImplementedError(
            "Artifact download not yet implemented. "
            "Use file-based storage with actions/cache for now."
        )
