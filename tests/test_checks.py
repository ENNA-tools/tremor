"""Tests for all Tremor check modules."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from tremor.config import DEFAULT_CONFIG
from tremor.parsers import WorkflowFile
from tremor.checks.pinning import UnpinnedActionCheck, MutableTagCheck
from tremor.checks.triggers import DangerousTriggerCheck, UntrustedPRCheckoutCheck
from tremor.checks.injection import ScriptInjectionCheck
from tremor.checks.permissions import ExcessivePermissionsCheck
from tremor.checks.secrets import SecretExposureCheck
from tremor.models import Severity, CheckID

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str) -> WorkflowFile:
    return WorkflowFile.from_path(FIXTURES / name)


class TestUnpinnedAction:
    def test_detects_tag_ref(self):
        wf = load_fixture("vulnerable.yml")
        check = UnpinnedActionCheck(DEFAULT_CONFIG)
        findings = check.run(wf)
        unpinned = [f for f in findings if "actions/checkout@v4" in f.title or "actions/setup-node@v4" in f.title]
        assert len(unpinned) >= 2

    def test_detects_branch_ref(self):
        wf = load_fixture("vulnerable.yml")
        check = UnpinnedActionCheck(DEFAULT_CONFIG)
        findings = check.run(wf)
        branch_refs = [f for f in findings if "@main" in f.title]
        assert len(branch_refs) == 1

    def test_clean_passes(self):
        wf = load_fixture("clean.yml")
        check = UnpinnedActionCheck(DEFAULT_CONFIG)
        findings = check.run(wf)
        assert len(findings) == 0


class TestMutableTag:
    def test_detects_major_version_tag(self):
        wf = load_fixture("vulnerable.yml")
        check = MutableTagCheck(DEFAULT_CONFIG)
        findings = check.run(wf)
        assert any("v4" in f.title for f in findings)

    def test_clean_passes(self):
        wf = load_fixture("clean.yml")
        check = MutableTagCheck(DEFAULT_CONFIG)
        findings = check.run(wf)
        assert len(findings) == 0


class TestDangerousTrigger:
    def test_detects_pull_request_target(self):
        wf = load_fixture("vulnerable.yml")
        check = DangerousTriggerCheck(DEFAULT_CONFIG)
        findings = check.run(wf)
        assert any(f.check_id == CheckID.DANGEROUS_TRIGGER and "pull_request_target" in f.title for f in findings)
        prt = [f for f in findings if "pull_request_target" in f.title][0]
        assert prt.severity == Severity.CRITICAL

    def test_detects_issue_comment(self):
        wf = load_fixture("vulnerable.yml")
        check = DangerousTriggerCheck(DEFAULT_CONFIG)
        findings = check.run(wf)
        assert any("issue_comment" in f.title for f in findings)


class TestUntrustedPRCheckout:
    def test_detects_pr_head_checkout(self):
        wf = load_fixture("vulnerable.yml")
        check = UntrustedPRCheckoutCheck(DEFAULT_CONFIG)
        findings = check.run(wf)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL


class TestScriptInjection:
    def test_detects_pr_title_injection(self):
        wf = load_fixture("vulnerable.yml")
        check = ScriptInjectionCheck(DEFAULT_CONFIG)
        findings = check.run(wf)
        assert any("pull_request.title" in f.title for f in findings)

    def test_detects_commit_message_injection(self):
        wf = load_fixture("vulnerable.yml")
        check = ScriptInjectionCheck(DEFAULT_CONFIG)
        findings = check.run(wf)
        assert any("head_commit.message" in f.title for f in findings)

    def test_clean_passes(self):
        wf = load_fixture("clean.yml")
        check = ScriptInjectionCheck(DEFAULT_CONFIG)
        findings = check.run(wf)
        assert len(findings) == 0


class TestExcessivePermissions:
    def test_detects_missing_permissions(self):
        wf = load_fixture("vulnerable.yml")
        check = ExcessivePermissionsCheck(DEFAULT_CONFIG)
        findings = check.run(wf)
        assert any("No top-level permissions" in f.title for f in findings)

    def test_explicit_read_passes(self):
        wf = load_fixture("clean.yml")
        check = ExcessivePermissionsCheck(DEFAULT_CONFIG)
        findings = check.run(wf)
        assert len(findings) == 0


class TestSecretExposure:
    def test_detects_secret_in_run(self):
        wf = load_fixture("vulnerable.yml")
        check = SecretExposureCheck(DEFAULT_CONFIG)
        findings = check.run(wf)
        assert len(findings) >= 1
        assert findings[0].check_id == CheckID.SECRET_IN_EXPRESSION
