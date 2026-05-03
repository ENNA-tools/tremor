"""SARIF v2.1.0 output for GitHub Code Scanning integration.

Converts PipelineScanResult into SARIF format for upload to GitHub's
code scanning API or as a GitHub Actions artifact.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import json
from typing import Any

from .models import ArtifactScan, FindingType, PipelineScanResult, StegFinding


# Map anomaly score ranges to SARIF severity levels
def _severity(score: float) -> str:
    if score >= 75:
        return "error"
    if score >= 50:
        return "warning"
    if score >= 25:
        return "note"
    return "none"


def _finding_level(confidence: float) -> str:
    if confidence >= 0.7:
        return "error"
    if confidence >= 0.4:
        return "warning"
    return "note"


# Map FindingType to SARIF rule definitions
_RULE_DEFS: dict[str, dict[str, Any]] = {
    FindingType.LSB_ANOMALY.value: {
        "shortDescription": {"text": "LSB steganography anomaly detected"},
        "helpUri": "https://en.wikipedia.org/wiki/Steganography#Digital_steganography",
    },
    FindingType.APPENDED_DATA.value: {
        "shortDescription": {"text": "Data appended after format terminator"},
    },
    FindingType.STEG_TOOL_SIGNATURE.value: {
        "shortDescription": {"text": "Known steganography tool signature found"},
    },
    FindingType.CHI_SQUARE_ANOMALY.value: {
        "shortDescription": {"text": "Chi-square uniformity anomaly in pixel data"},
    },
    FindingType.POLYGLOT.value: {
        "shortDescription": {"text": "Polyglot file — valid as multiple formats"},
    },
    FindingType.HIDDEN_FILE.value: {
        "shortDescription": {"text": "Hidden or sensitive file in archive"},
    },
    FindingType.MULTI_LAYER_ENCODING.value: {
        "shortDescription": {"text": "Multi-layer encoded payload detected"},
    },
    FindingType.OBFUSCATED_COMMAND.value: {
        "shortDescription": {"text": "Obfuscated command pattern"},
    },
    FindingType.POSTINSTALL_PAYLOAD.value: {
        "shortDescription": {"text": "Suspicious install script in package manifest"},
    },
    FindingType.HIGH_ENTROPY_SECTION.value: {
        "shortDescription": {"text": "High-entropy section in binary"},
    },
    FindingType.EMBEDDED_STRINGS.value: {
        "shortDescription": {"text": "Encoded strings embedded in binary"},
    },
}


def _make_rule(finding_type: str) -> dict[str, Any]:
    """Build a SARIF rule object for a finding type."""
    rule: dict[str, Any] = {
        "id": f"epicenter/{finding_type}",
        "name": finding_type,
    }
    if finding_type in _RULE_DEFS:
        rule.update(_RULE_DEFS[finding_type])
    else:
        rule["shortDescription"] = {"text": finding_type.replace("_", " ").title()}
    return rule


def _make_result(finding: StegFinding, scan: ArtifactScan) -> dict[str, Any]:
    """Build a SARIF result object from a StegFinding."""
    result: dict[str, Any] = {
        "ruleId": f"epicenter/{finding.finding_type.value}",
        "level": _finding_level(finding.confidence),
        "message": {"text": finding.description or finding.finding_type.value},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": scan.path},
                },
            }
        ],
        "properties": {
            "confidence": finding.confidence,
            "anomalyScore": scan.anomaly_score,
        },
    }

    if finding.offset > 0:
        result["locations"][0]["physicalLocation"]["region"] = {
            "byteOffset": finding.offset,
            "byteLength": finding.size or 0,
        }

    if finding.evidence:
        result["properties"]["evidence"] = finding.evidence[:500]

    return result


def to_sarif(pipeline_result: PipelineScanResult) -> dict[str, Any]:
    """Convert a PipelineScanResult to SARIF v2.1.0 format."""
    # Collect all unique finding types for rules
    finding_types: set[str] = set()
    results: list[dict[str, Any]] = []

    for scan in pipeline_result.scans:
        for finding in scan.findings:
            ft = finding.finding_type.value
            finding_types.add(ft)
            results.append(_make_result(finding, scan))

    rules = [_make_rule(ft) for ft in sorted(finding_types)]
    rule_index = {ft: i for i, ft in enumerate(sorted(finding_types))}

    # Add ruleIndex to each result
    for r in results:
        rule_id = r["ruleId"].removeprefix("epicenter/")
        if rule_id in rule_index:
            r["ruleIndex"] = rule_index[rule_id]

    sarif: dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "epicenter",
                        "semanticVersion": "0.1.0",
                        "informationUri": "https://github.com/1oosedows/tremor",
                        "rules": rules,
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "properties": {
                            "target": pipeline_result.target,
                            "totalArtifacts": pipeline_result.total_artifacts,
                            "flaggedArtifacts": pipeline_result.flagged_artifacts,
                            "overallScore": pipeline_result.overall_score,
                        },
                    }
                ],
            }
        ],
    }

    return sarif


def to_sarif_json(pipeline_result: PipelineScanResult, indent: int = 2) -> str:
    """Convert to SARIF and return as formatted JSON string."""
    return json.dumps(to_sarif(pipeline_result), indent=indent, default=str)
