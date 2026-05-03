"""Tests for baseline management."""

import sys
import json
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from tremor.baseline import BaselineStore, AnomalyDetector


class TestBaselineStore:
    def test_load_missing_returns_none(self):
        store = BaselineStore()
        assert store.load("/nonexistent/path.json") is None

    def test_save_and_load(self, tmp_path):
        store = BaselineStore()
        path = str(tmp_path / "baseline.json")
        data = {"version": 2, "snapshots": [], "aggregated": {}}
        store.save(path, data)
        loaded = store.load(path)
        assert loaded == data

    def test_save_creates_parents(self, tmp_path):
        store = BaselineStore()
        path = str(tmp_path / "deep" / "nested" / "baseline.json")
        store.save(path, {"version": 2})
        assert Path(path).exists()

    def test_new_baseline(self):
        store = BaselineStore()
        snapshot = {
            "network_hosts": ["github.com"],
            "process_commands": ["node", "git"],
            "env_secret_names": ["GITHUB_TOKEN"],
            "step_durations": {"build": 12.5},
        }
        baseline = store.new_baseline(snapshot)
        assert baseline["version"] == 2
        assert len(baseline["snapshots"]) == 1
        assert "github.com" in baseline["aggregated"]["known_hosts"]
        assert "node" in baseline["aggregated"]["known_processes"]

    def test_merge_adds_snapshot(self):
        store = BaselineStore()
        existing = store.new_baseline({
            "network_hosts": ["github.com"],
            "process_commands": ["node"],
            "env_secret_names": [],
        })
        new_snapshot = {
            "network_hosts": ["github.com", "npm.registry.org"],
            "process_commands": ["node", "npm"],
            "env_secret_names": ["NPM_TOKEN"],
        }
        merged = store.merge(existing, new_snapshot)
        assert len(merged["snapshots"]) == 2
        assert "npm.registry.org" in merged["aggregated"]["known_hosts"]
        assert "NPM_TOKEN" in merged["aggregated"]["known_secrets"]

    def test_merge_trims_window(self):
        store = BaselineStore()
        existing = store.new_baseline({"network_hosts": []})
        for i in range(25):
            existing = store.merge(existing, {"network_hosts": [f"host-{i}"]}, window=10)
        assert len(existing["snapshots"]) == 10


class TestAnomalyDetector:
    def setup_method(self):
        self.detector = AnomalyDetector()

    def test_detect_new_hosts(self):
        baseline = {"github.com", "npm.org"}
        current = {"github.com", "npm.org", "evil.com"}
        assert self.detector.detect_new_hosts(baseline, current) == ["evil.com"]

    def test_detect_no_new_hosts(self):
        baseline = {"github.com", "npm.org"}
        current = {"github.com"}
        assert self.detector.detect_new_hosts(baseline, current) == []

    def test_detect_new_processes(self):
        baseline = {"node", "git", "npm"}
        current = {"node", "git", "npm", "curl", "xmrig"}
        new = self.detector.detect_new_processes(baseline, current)
        assert "curl" in new
        assert "xmrig" in new

    def test_timing_anomaly_true(self):
        durations = [10.0, 11.0, 10.5, 10.2, 11.3, 10.8]
        assert self.detector.detect_timing_anomaly(durations, 25.0)

    def test_timing_anomaly_false(self):
        durations = [10.0, 11.0, 10.5, 10.2, 11.3, 10.8]
        assert not self.detector.detect_timing_anomaly(durations, 10.9)

    def test_timing_anomaly_insufficient_data(self):
        assert not self.detector.detect_timing_anomaly([10.0], 100.0)

    def test_timing_anomaly_zero_stddev(self):
        assert self.detector.detect_timing_anomaly([10.0, 10.0, 10.0], 10.5)
        assert not self.detector.detect_timing_anomaly([10.0, 10.0, 10.0], 10.0)

    def test_detect_new_secrets(self):
        baseline = {"GITHUB_TOKEN"}
        current = {"GITHUB_TOKEN", "DEPLOY_KEY"}
        assert self.detector.detect_new_secrets(baseline, current) == ["DEPLOY_KEY"]
