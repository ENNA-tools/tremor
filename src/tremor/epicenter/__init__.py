"""Epicenter — CI/CD pipeline steganography and anomaly detector.

Ported from arterial/pith into the tremor pipeline security framework.
"""

from .engine import scan, scan_path
from .scanner import scan_artifact
from .sarif import to_sarif, to_sarif_json
from .models import (
    ArtifactType,
    FindingType,
    StegFinding,
    ArtifactScan,
    PipelineScanResult,
)

__version__ = "0.1.0"

__all__ = [
    "scan",
    "scan_path",
    "scan_artifact",
    "ArtifactType",
    "FindingType",
    "StegFinding",
    "ArtifactScan",
    "PipelineScanResult",
    "to_sarif",
    "to_sarif_json",
]
