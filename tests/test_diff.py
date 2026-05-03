"""Tests for trust surface diff analysis."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from tremor.models import Severity
from tremor.diff import (
    WorkflowDiffAnalyzer,
    ChangedFile,
    TrustSurfaceChange,
    DiffReport,
    format_pr_comment,
    _extract_uses,
    _extract_triggers,
    _extract_permissions,
    _extract_secret_refs,
    _parse_action_ref,
    _is_sha,
)


class TestHelpers:
    def test_extract_uses(self):
        data = {
            "jobs": {
                "build": {
                    "steps": [
                        {"uses": "actions/checkout@v4"},
                        {"run": "echo hello"},
                        {"uses": "actions/setup-node@v4"},
                    ]
                }
            }
        }
        uses = _extract_uses(data)
        assert uses == {"actions/checkout@v4", "actions/setup-node@v4"}

    def test_extract_triggers_string(self):
        assert _extract_triggers({"on": "push"}) == {"push": None}

    def test_extract_triggers_list(self):
        assert _extract_triggers({"on": ["push", "pull_request"]}) == {
            "push": None, "pull_request": None,
        }

    def test_extract_triggers_dict(self):
        data = {"on": {"push": {"branches": ["main"]}, "pull_request": None}}
        triggers = _extract_triggers(data)
        assert "push" in triggers
        assert triggers["push"] == {"branches": ["main"]}

    def test_extract_permissions_none(self):
        assert _extract_permissions({}) is None

    def test_extract_permissions_dict(self):
        data = {"permissions": {"contents": "read", "packages": "write"}}
        assert _extract_permissions(data) == {"contents": "read", "packages": "write"}

    def test_extract_secret_refs(self):
        content = """
        run: |
          curl -H "Auth: ${{ secrets.DEPLOY_TOKEN }}" url
          echo ${{ secrets.NPM_TOKEN }}
        """
        refs = _extract_secret_refs(content)
        assert refs == {"DEPLOY_TOKEN", "NPM_TOKEN"}

    def test_extract_secret_refs_none(self):
        assert _extract_secret_refs(None) == set()

    def test_parse_action_ref(self):
        assert _parse_action_ref("actions/checkout@v4") == ("actions/checkout", "v4")
        assert _parse_action_ref("actions/checkout@abc123") == ("actions/checkout", "abc123")
        assert _parse_action_ref("./local-action") == ("./local-action", "")

    def test_is_sha(self):
        assert _is_sha("b4ffde65f46336ab88eb53be808477a3936bae11")
        assert not _is_sha("v4")
        assert not _is_sha("main")


class TestAnalyzeNewWorkflow:
    def test_new_workflow_with_dangerous_trigger(self):
        cf = ChangedFile(
            path=".github/workflows/deploy.yml",
            status="added",
            old_content=None,
            new_content="""
name: Deploy
on: pull_request_target
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: some-org/deploy-action@v1
""",
        )
        from tremor.config import DEFAULT_CONFIG
        analyzer = WorkflowDiffAnalyzer(DEFAULT_CONFIG)
        changes = analyzer._analyze_new_workflow(cf)

        categories = [c.category for c in changes]
        assert "new_workflow" in categories
        assert "new_action" in categories
        assert "new_trigger" in categories

        prt = [c for c in changes if c.category == "new_trigger"]
        assert any("pull_request_target" in c.detail for c in prt)


class TestAnalyzeModifiedWorkflow:
    def test_permission_escalation(self):
        cf = ChangedFile(
            path=".github/workflows/ci.yml",
            status="modified",
            old_content="""
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""",
            new_content="""
permissions:
  contents: write
  packages: write
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""",
        )
        from tremor.config import DEFAULT_CONFIG
        analyzer = WorkflowDiffAnalyzer(DEFAULT_CONFIG)
        changes = analyzer._analyze_modified_workflow(cf)

        escalations = [c for c in changes if c.category == "permission_escalation"]
        assert len(escalations) >= 1
        assert any("contents" in c.detail for c in escalations)

    def test_new_action_detected(self):
        cf = ChangedFile(
            path=".github/workflows/ci.yml",
            status="modified",
            old_content="""
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""",
            new_content="""
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: evil-org/supply-chain@v1
""",
        )
        from tremor.config import DEFAULT_CONFIG
        analyzer = WorkflowDiffAnalyzer(DEFAULT_CONFIG)
        changes = analyzer._analyze_modified_workflow(cf)

        new_actions = [c for c in changes if c.category == "new_action"]
        assert len(new_actions) == 1
        assert "evil-org/supply-chain" in new_actions[0].detail

    def test_sha_to_tag_downgrade(self):
        cf = ChangedFile(
            path=".github/workflows/ci.yml",
            status="modified",
            old_content="""
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
""",
            new_content="""
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
""",
        )
        from tremor.config import DEFAULT_CONFIG
        analyzer = WorkflowDiffAnalyzer(DEFAULT_CONFIG)
        changes = analyzer._analyze_modified_workflow(cf)

        version_changes = [c for c in changes if c.category == "action_version_change"]
        assert len(version_changes) == 1
        assert version_changes[0].severity == Severity.HIGH
        assert "mutable tag" in version_changes[0].detail

    def test_new_secret_ref(self):
        cf = ChangedFile(
            path=".github/workflows/ci.yml",
            status="modified",
            old_content="""
jobs:
  test:
    steps:
      - run: echo hello
""",
            new_content="""
jobs:
  test:
    steps:
      - run: curl -H "${{ secrets.DEPLOY_KEY }}" url
""",
        )
        from tremor.config import DEFAULT_CONFIG
        analyzer = WorkflowDiffAnalyzer(DEFAULT_CONFIG)
        changes = analyzer._analyze_modified_workflow(cf)

        secrets = [c for c in changes if c.category == "new_secret_ref"]
        assert len(secrets) == 1
        assert "DEPLOY_KEY" in secrets[0].detail


class TestDiffReport:
    def test_empty_report(self):
        report = DiffReport(changes=[], summary="No changes", risk_delta=0)
        comment = format_pr_comment(report)
        assert "No security-relevant changes" in comment

    def test_report_with_changes(self):
        changes = [
            TrustSurfaceChange(
                category="new_action",
                severity=Severity.MEDIUM,
                description="New action: evil/thing@v1",
                file=".github/workflows/ci.yml",
                detail="evil/thing@v1",
            ),
            TrustSurfaceChange(
                category="permission_escalation",
                severity=Severity.HIGH,
                description="Permission escalated: contents write",
                file=".github/workflows/ci.yml",
                detail="contents: write",
            ),
        ]
        report = DiffReport(
            changes=changes,
            summary="2 trust surface change(s)",
            risk_delta=22,
        )
        comment = format_pr_comment(report)
        assert "Trust Surface Diff" in comment
        assert "evil/thing" in comment
        assert "contents" in comment
        assert "+22" in comment
