"""Epicenter data models — CI/CD steganography and anomaly detection.

Stdlib-only dataclass equivalents of the original pydantic models from
arterial/pith. No pydantic dependency.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class ArtifactType(str, Enum):
    """Classification of CI/CD artifact types."""
    BUILD_LOG = "build_log"
    CONTAINER_LAYER = "container_layer"
    TEST_OUTPUT = "test_output"
    PACKAGE_ARTIFACT = "package_artifact"
    BINARY = "binary"
    IMAGE = "image"
    ARCHIVE = "archive"
    WORKFLOW = "workflow"
    SCRIPT = "script"
    CONFIG = "config"
    UNKNOWN = "unknown"


class FindingType(str, Enum):
    """Types of steganographic or anomalous findings."""
    # Image steganography
    LSB_ANOMALY = "lsb_anomaly"
    APPENDED_DATA = "appended_data"
    STEG_TOOL_SIGNATURE = "steg_tool_signature"
    CHI_SQUARE_ANOMALY = "chi_square_anomaly"

    # Archive anomalies
    POLYGLOT = "polyglot"
    HIDDEN_FILE = "hidden_file"
    COMPRESSION_RATIO_ANOMALY = "compression_ratio_anomaly"

    # Encoded payloads
    ENCODED_PAYLOAD = "encoded_payload"
    BASE64_BLOCK = "base64_block"
    HEX_BLOCK = "hex_block"
    URL_ENCODED_BLOCK = "url_encoded_block"
    MULTI_LAYER_ENCODING = "multi_layer_encoding"

    # Build artifact anomalies
    OBFUSCATED_COMMAND = "obfuscated_command"
    POSTINSTALL_PAYLOAD = "postinstall_payload"
    DOCKER_SUSPICIOUS_LAYER = "docker_suspicious_layer"
    WORKFLOW_OBFUSCATION = "workflow_obfuscation"

    # Binary anomalies
    HIGH_ENTROPY = "high_entropy"
    HIGH_ENTROPY_SECTION = "high_entropy_section"
    UNUSUAL_SECTION_SIZE = "unusual_section_size"
    EMBEDDED_STRINGS = "embedded_strings"

    # General
    SIZE_ANOMALY = "size_anomaly"
    ENTROPY_ANOMALY = "entropy_anomaly"
    METADATA_PADDING = "metadata_padding"
    UNEXPECTED_BINARY = "unexpected_binary"


@dataclass
class StegFinding:
    """Individual steganographic or anomalous finding."""
    finding_type: FindingType
    confidence: float = 0.0
    description: str = ""
    evidence: str = ""
    location: str = ""
    offset: int = 0
    size: int = 0
    extracted_preview: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.confidence = max(0.0, min(1.0, self.confidence))

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_type": self.finding_type.value,
            "confidence": self.confidence,
            "description": self.description,
            "evidence": self.evidence,
            "location": self.location,
            "offset": self.offset,
            "size": self.size,
            "extracted_preview": self.extracted_preview,
            "metadata": self.metadata,
        }


@dataclass
class ArtifactScan:
    """Scan result for a single artifact."""
    path: str = ""
    artifact_type: ArtifactType = ArtifactType.UNKNOWN
    file_size: int = 0
    entropy: float = 0.0
    anomaly_score: float = 0.0
    findings: list[StegFinding] = field(default_factory=list)
    high_entropy_regions: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""

    def __post_init__(self) -> None:
        self.anomaly_score = max(0.0, min(100.0, self.anomaly_score))

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "artifact_type": self.artifact_type.value,
            "file_size": self.file_size,
            "entropy": self.entropy,
            "anomaly_score": self.anomaly_score,
            "findings": [f.to_dict() for f in self.findings],
            "high_entropy_regions": self.high_entropy_regions,
            "error": self.error,
        }


@dataclass
class PipelineScanResult:
    """Aggregate scan result for a CI/CD pipeline target."""
    target: str = ""
    ci_provider: str = ""
    total_artifacts: int = 0
    flagged_artifacts: int = 0
    scans: list[ArtifactScan] = field(default_factory=list)
    overall_score: float = 0.0
    finding_summary: dict[str, int] = field(default_factory=dict)
    scanned_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __post_init__(self) -> None:
        self.overall_score = max(0.0, min(100.0, self.overall_score))

    def compute_summary(self) -> None:
        """Populate finding_summary from scan results."""
        counts: dict[str, int] = {}
        for scan in self.scans:
            for f in scan.findings:
                counts[f.finding_type.value] = counts.get(f.finding_type.value, 0) + 1
        self.finding_summary = counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "ci_provider": self.ci_provider,
            "total_artifacts": self.total_artifacts,
            "flagged_artifacts": self.flagged_artifacts,
            "scans": [s.to_dict() for s in self.scans],
            "overall_score": self.overall_score,
            "finding_summary": self.finding_summary,
            "scanned_at": self.scanned_at.isoformat(),
        }
