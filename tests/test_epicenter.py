"""Tests for epicenter artifact scanning."""

import sys
import os
import json
import base64
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from tremor.epicenter.models import (
    ArtifactType, FindingType, StegFinding, ArtifactScan, PipelineScanResult,
)
from tremor.epicenter.entropy import (
    shannon_entropy, byte_frequency, chi_square_byte_test,
    high_entropy_regions, lsb_plane_entropy,
)
from tremor.epicenter.decoders import (
    detect_base64_blocks, detect_hex_blocks, detect_all_encodings,
    try_decode_base64, decode_blob, DecodedBlob,
)
from tremor.epicenter.scanner import detect_artifact_type, scan_artifact
from tremor.epicenter.engine import scan_path
from tremor.epicenter.sarif import to_sarif, to_sarif_json

ARTIFACTS = Path(__file__).parent / "fixtures" / "artifacts"


class TestEntropy:
    def test_zero_entropy(self):
        assert shannon_entropy(b"\x00" * 1000) == 0.0

    def test_max_entropy(self):
        data = bytes(range(256)) * 100
        ent = shannon_entropy(data)
        assert ent > 7.9

    def test_byte_frequency(self):
        freq = byte_frequency(b"\x00\x00\x01\x01\x01")
        assert freq[0] == 2
        assert freq[1] == 3
        assert sum(freq) == 5

    def test_high_entropy_regions(self):
        low = b"\x00" * 8192
        high = os.urandom(8192)
        data = low + high + low
        regions = high_entropy_regions(data, threshold=7.0)
        assert len(regions) >= 1
        assert regions[0]["offset"] >= 4096

    def test_chi_square_uniform(self):
        data = bytes(range(256)) * 400
        chi2, p = chi_square_byte_test(data)
        assert chi2 < 1.0

    def test_lsb_plane_entropy_random(self):
        data = os.urandom(1000)
        ent = lsb_plane_entropy(data)
        assert ent > 6.0


class TestDecoders:
    def test_detect_base64(self):
        text = "prefix " + base64.b64encode(os.urandom(60)).decode() + " suffix"
        detections = detect_base64_blocks(text, min_length=40)
        assert len(detections) >= 1

    def test_detect_hex(self):
        text = "data: " + os.urandom(40).hex() + " end"
        detections = detect_hex_blocks(text, min_bytes=16)
        assert len(detections) >= 1

    def test_try_decode_base64(self):
        original = b"Hello World!"
        encoded = base64.b64encode(original).decode()
        decoded = try_decode_base64(encoded)
        assert decoded == original

    def test_detect_all_returns_sorted(self):
        b64 = base64.b64encode(os.urandom(60)).decode()
        hexblob = os.urandom(40).hex()
        text = f"start {hexblob} middle {b64} end"
        dets = detect_all_encodings(text)
        offsets = [d.offset for d in dets]
        assert offsets == sorted(offsets)


class TestModels:
    def test_steg_finding_clamps_confidence(self):
        f = StegFinding(finding_type=FindingType.HIGH_ENTROPY, confidence=1.5)
        assert f.confidence == 1.0
        f2 = StegFinding(finding_type=FindingType.HIGH_ENTROPY, confidence=-0.5)
        assert f2.confidence == 0.0

    def test_artifact_scan_to_dict(self):
        scan = ArtifactScan(
            path="/test",
            artifact_type=ArtifactType.BINARY,
            anomaly_score=42.0,
            findings=[StegFinding(
                finding_type=FindingType.HIGH_ENTROPY,
                confidence=0.8,
                description="test finding",
            )],
        )
        d = scan.to_dict()
        assert d["path"] == "/test"
        assert d["artifact_type"] == "binary"
        assert len(d["findings"]) == 1
        assert d["findings"][0]["finding_type"] == "high_entropy"

    def test_pipeline_result_compute_summary(self):
        result = PipelineScanResult(
            target="/test",
            scans=[ArtifactScan(
                path="/test/a",
                findings=[
                    StegFinding(finding_type=FindingType.HIGH_ENTROPY),
                    StegFinding(finding_type=FindingType.HIGH_ENTROPY),
                    StegFinding(finding_type=FindingType.OBFUSCATED_COMMAND),
                ],
            )],
        )
        result.compute_summary()
        assert result.finding_summary["high_entropy"] == 2
        assert result.finding_summary["obfuscated_command"] == 1


class TestArtifactDetection:
    def test_detect_script(self, tmp_path):
        script = tmp_path / "deploy.sh"
        script.write_text("#!/bin/bash\necho hello")
        assert detect_artifact_type(script) == ArtifactType.SCRIPT

    def test_detect_binary(self, tmp_path):
        binary = tmp_path / "app.exe"
        binary.write_bytes(b"MZ" + b"\x00" * 100)
        assert detect_artifact_type(binary) == ArtifactType.BINARY

    def test_detect_image_png(self, tmp_path):
        png = tmp_path / "logo.png"
        png.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        assert detect_artifact_type(png) == ArtifactType.IMAGE

    def test_detect_archive(self, tmp_path):
        archive = tmp_path / "bundle.zip"
        archive.write_bytes(b"PK\x03\x04" + b"\x00" * 100)
        assert detect_artifact_type(archive) == ArtifactType.ARCHIVE


class TestScanner:
    def test_scan_obfuscated_script(self):
        if not ARTIFACTS.exists():
            pytest.skip("artifact fixtures not created")
        result = scan_artifact(ARTIFACTS / "deploy.sh")
        assert result.anomaly_score > 0
        types = {f.finding_type for f in result.findings}
        assert FindingType.OBFUSCATED_COMMAND in types

    def test_scan_suspicious_package(self):
        if not ARTIFACTS.exists():
            pytest.skip("artifact fixtures not created")
        result = scan_artifact(ARTIFACTS / "package.json")
        types = {f.finding_type for f in result.findings}
        assert FindingType.POSTINSTALL_PAYLOAD in types

    def test_scan_high_entropy_binary(self):
        if not ARTIFACTS.exists():
            pytest.skip("artifact fixtures not created")
        result = scan_artifact(ARTIFACTS / "suspicious.bin")
        types = {f.finding_type for f in result.findings}
        assert FindingType.HIGH_ENTROPY in types

    def test_scan_clean_file(self, tmp_path):
        clean = tmp_path / "readme.txt"
        clean.write_text("This is a normal text file with no suspicious content.\n" * 10)
        result = scan_artifact(clean)
        assert result.anomaly_score == 0


class TestEngine:
    def test_scan_path_directory(self):
        if not ARTIFACTS.exists():
            pytest.skip("artifact fixtures not created")
        result = scan_path(str(ARTIFACTS))
        assert result.total_artifacts == 3
        assert result.flagged_artifacts >= 1
        assert result.overall_score > 0

    def test_scan_path_single_file(self):
        if not ARTIFACTS.exists():
            pytest.skip("artifact fixtures not created")
        result = scan_path(str(ARTIFACTS / "deploy.sh"))
        assert result.total_artifacts == 1

    def test_scan_nonexistent(self):
        result = scan_path("/nonexistent/path")
        assert result.total_artifacts == 0


class TestSARIF:
    def test_sarif_structure(self):
        result = PipelineScanResult(
            target="/test",
            scans=[ArtifactScan(
                path="/test/evil.sh",
                anomaly_score=75.0,
                findings=[StegFinding(
                    finding_type=FindingType.OBFUSCATED_COMMAND,
                    confidence=0.8,
                    description="curl pipe to shell",
                    location="/test/evil.sh",
                )],
            )],
        )
        sarif = to_sarif(result)
        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["tool"]["driver"]["name"] == "epicenter"
        assert len(sarif["runs"][0]["results"]) == 1

    def test_sarif_json_output(self):
        result = PipelineScanResult(target="/test")
        output = to_sarif_json(result)
        parsed = json.loads(output)
        assert parsed["version"] == "2.1.0"
