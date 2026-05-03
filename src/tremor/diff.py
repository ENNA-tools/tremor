"""PR workflow diff analysis — trust surface change detection."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from tremor.models import Severity


@dataclass
class ChangedFile:
    path: str
    status: str
    old_content: str | None
    new_content: str | None


@dataclass
class TrustSurfaceChange:
    category: str
    severity: Severity
    description: str
    file: str
    detail: str


@dataclass
class DiffReport:
    changes: list[TrustSurfaceChange]
    summary: str
    risk_delta: int


DANGEROUS_TRIGGERS = {"pull_request_target", "workflow_run", "workflow_dispatch"}
WRITE_PERMISSIONS = {"write", "write-all"}


def _run_git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        capture_output=True,
        text=True,
        check=False,
    )


def _parse_yaml(content: str | None) -> dict[str, Any]:
    if not content:
        return {}
    try:
        return yaml.safe_load(content) or {}
    except yaml.YAMLError:
        return {}


def _extract_uses(data: dict) -> set[str]:
    refs = set()
    for job in data.get("jobs", {}).values():
        for step in job.get("steps", []):
            if "uses" in step:
                refs.add(step["uses"])
    return refs


def _extract_triggers(data: dict) -> dict[str, Any]:
    on = data.get("on") or data.get(True) or {}
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return {t: None for t in on}
    return dict(on)


def _extract_permissions(data: dict) -> dict[str, str] | str | None:
    return data.get("permissions")


def _extract_secret_refs(content: str | None) -> set[str]:
    if not content:
        return set()
    return set(re.findall(r"\$\{\{\s*secrets\.([A-Z_a-z0-9]+)\s*\}\}", content))


def _extract_environments(data: dict) -> dict[str, str | None]:
    """Map job_name -> environment name (None if no environment set)."""
    envs = {}
    for name, job in data.get("jobs", {}).items():
        env = job.get("environment")
        if isinstance(env, dict):
            envs[name] = env.get("name")
        elif isinstance(env, str):
            envs[name] = env
        else:
            envs[name] = None
    return envs


def _extract_run_blocks(data: dict) -> dict[str, list[str]]:
    """Map 'job.step_index' -> run script content."""
    blocks = {}
    for job_name, job in data.get("jobs", {}).items():
        for i, step in enumerate(job.get("steps", [])):
            if "run" in step:
                blocks[f"{job_name}.{i}"] = step["run"]
    return blocks


def _parse_action_ref(ref: str) -> tuple[str, str]:
    """Split 'owner/repo@version' into (owner/repo, version)."""
    if "@" in ref:
        parts = ref.rsplit("@", 1)
        return parts[0], parts[1]
    return ref, ""


def _is_sha(version: str) -> bool:
    return bool(re.match(r"^[0-9a-f]{40}$", version))


def _permissions_to_dict(perms: dict | str | None) -> dict[str, str]:
    if perms is None:
        return {}
    if isinstance(perms, str):
        return {"_all": perms}
    return dict(perms)


class WorkflowDiffAnalyzer:
    def __init__(self, config: dict, base_ref: str = "origin/main"):
        self.config = config
        self.base_ref = base_ref
        self.workflow_dirs = config.get("workflow_paths", [".github/workflows"])

    def get_changed_workflows(self) -> list[ChangedFile]:
        result = _run_git("diff", "--name-status", f"{self.base_ref}...HEAD")
        if result.returncode != 0:
            return []

        changed = []
        for line in result.stdout.strip().splitlines():
            if not line:
                continue
            parts = line.split("\t", 1)
            if len(parts) != 2:
                continue
            status_code, path = parts[0], parts[1]

            if not any(path.startswith(d + "/") or path.startswith(d.rstrip("/") + "/")
                       for d in self.workflow_dirs):
                continue

            if not (path.endswith(".yml") or path.endswith(".yaml")):
                continue

            status = {"A": "added", "M": "modified", "D": "deleted"}.get(status_code[0])
            if not status:
                continue

            old_content = self._get_old_content(path) if status != "added" else None
            new_content = self._get_new_content(path) if status != "deleted" else None

            changed.append(ChangedFile(
                path=path,
                status=status,
                old_content=old_content,
                new_content=new_content,
            ))

        return changed

    def _get_old_content(self, path: str) -> str | None:
        result = _run_git("show", f"{self.base_ref}:{path}")
        if result.returncode != 0:
            return None
        return result.stdout

    def _get_new_content(self, path: str) -> str | None:
        try:
            return Path(path).read_text()
        except (OSError, FileNotFoundError):
            return None

    def analyze(self) -> DiffReport:
        changed_files = self.get_changed_workflows()
        changes: list[TrustSurfaceChange] = []

        for cf in changed_files:
            changes.extend(self._analyze_file(cf))

        changes.sort(key=lambda c: (-c.severity.rank, c.category, c.file))

        risk_delta = self._compute_risk_delta(changes)
        summary = self._build_summary(changes, risk_delta)

        return DiffReport(changes=changes, summary=summary, risk_delta=risk_delta)

    def _analyze_file(self, cf: ChangedFile) -> list[TrustSurfaceChange]:
        if cf.status == "added":
            return self._analyze_new_workflow(cf)
        if cf.status == "deleted":
            return self._analyze_deleted_workflow(cf)
        return self._analyze_modified_workflow(cf)

    def _analyze_new_workflow(self, cf: ChangedFile) -> list[TrustSurfaceChange]:
        changes = [TrustSurfaceChange(
            category="new_workflow",
            severity=Severity.HIGH,
            description="New workflow file added",
            file=cf.path,
            detail="Entire workflow requires review as new trust surface",
        )]

        data = _parse_yaml(cf.new_content)
        for ref in _extract_uses(data):
            changes.append(TrustSurfaceChange(
                category="new_action",
                severity=Severity.MEDIUM,
                description=f"New action reference: {ref}",
                file=cf.path,
                detail=ref,
            ))

        for trigger in _extract_triggers(data):
            if trigger in DANGEROUS_TRIGGERS:
                changes.append(TrustSurfaceChange(
                    category="new_trigger",
                    severity=Severity.HIGH,
                    description=f"Dangerous trigger in new workflow: {trigger}",
                    file=cf.path,
                    detail=trigger,
                ))

        for secret in _extract_secret_refs(cf.new_content):
            changes.append(TrustSurfaceChange(
                category="new_secret_ref",
                severity=Severity.MEDIUM,
                description=f"Secret reference: secrets.{secret}",
                file=cf.path,
                detail=f"secrets.{secret}",
            ))

        return changes

    def _analyze_deleted_workflow(self, cf: ChangedFile) -> list[TrustSurfaceChange]:
        return [TrustSurfaceChange(
            category="new_workflow",
            severity=Severity.LOW,
            description="Workflow file deleted",
            file=cf.path,
            detail="Workflow removed — trust surface reduced",
        )]

    def _analyze_modified_workflow(self, cf: ChangedFile) -> list[TrustSurfaceChange]:
        changes: list[TrustSurfaceChange] = []
        old_data = _parse_yaml(cf.old_content)
        new_data = _parse_yaml(cf.new_content)

        changes.extend(self._diff_actions(cf, old_data, new_data))
        changes.extend(self._diff_permissions(cf, old_data, new_data))
        changes.extend(self._diff_triggers(cf, old_data, new_data))
        changes.extend(self._diff_secrets(cf))
        changes.extend(self._diff_environments(cf, old_data, new_data))
        changes.extend(self._diff_scripts(cf, old_data, new_data))

        return changes

    def _diff_actions(self, cf: ChangedFile, old: dict, new: dict) -> list[TrustSurfaceChange]:
        changes = []
        old_uses = _extract_uses(old)
        new_uses = _extract_uses(new)

        added_refs = new_uses - old_uses
        for ref in sorted(added_refs):
            old_action, _ = _parse_action_ref(ref)
            prior_versions = [u for u in old_uses if _parse_action_ref(u)[0] == old_action]

            if prior_versions:
                old_ref = prior_versions[0]
                _, old_ver = _parse_action_ref(old_ref)
                _, new_ver = _parse_action_ref(ref)

                severity = Severity.MEDIUM
                detail = f"{old_ref} → {ref}"
                # SHA to tag is a security downgrade
                if _is_sha(old_ver) and not _is_sha(new_ver):
                    severity = Severity.HIGH
                    detail += " (pinned SHA → mutable tag)"

                changes.append(TrustSurfaceChange(
                    category="action_version_change",
                    severity=severity,
                    description=f"Action reference changed: {old_action}",
                    file=cf.path,
                    detail=detail,
                ))
            else:
                changes.append(TrustSurfaceChange(
                    category="new_action",
                    severity=Severity.MEDIUM,
                    description=f"New action reference: {ref}",
                    file=cf.path,
                    detail=ref,
                ))

        return changes

    def _diff_permissions(self, cf: ChangedFile, old: dict, new: dict) -> list[TrustSurfaceChange]:
        changes = []
        old_perms = _permissions_to_dict(_extract_permissions(old))
        new_perms = _permissions_to_dict(_extract_permissions(new))

        if old_perms and not new_perms:
            changes.append(TrustSurfaceChange(
                category="permission_removal",
                severity=Severity.HIGH,
                description="Permissions block removed",
                file=cf.path,
                detail="Removed explicit permissions — job may inherit default token permissions",
            ))
            return changes

        for scope, access in new_perms.items():
            old_access = old_perms.get(scope)
            if access in WRITE_PERMISSIONS and old_access not in WRITE_PERMISSIONS:
                if old_access is None:
                    desc = f"New write permission: {scope}: {access}"
                else:
                    desc = f"Permission escalated: {scope}: {old_access} → {access}"
                changes.append(TrustSurfaceChange(
                    category="permission_escalation",
                    severity=Severity.HIGH,
                    description=desc,
                    file=cf.path,
                    detail=f"{scope}: {access}",
                ))

        if "_all" in new_perms and new_perms["_all"] in WRITE_PERMISSIONS:
            if "_all" not in old_perms or old_perms["_all"] not in WRITE_PERMISSIONS:
                changes.append(TrustSurfaceChange(
                    category="permission_escalation",
                    severity=Severity.CRITICAL,
                    description="Global write-all permissions added",
                    file=cf.path,
                    detail=f"permissions: {new_perms['_all']}",
                ))

        return changes

    def _diff_triggers(self, cf: ChangedFile, old: dict, new: dict) -> list[TrustSurfaceChange]:
        changes = []
        old_triggers = _extract_triggers(old)
        new_triggers = _extract_triggers(new)

        added_triggers = set(new_triggers) - set(old_triggers)
        for trigger in sorted(added_triggers):
            severity = Severity.HIGH if trigger in DANGEROUS_TRIGGERS else Severity.MEDIUM
            changes.append(TrustSurfaceChange(
                category="new_trigger",
                severity=severity,
                description=f"New trigger added: {trigger}",
                file=cf.path,
                detail=trigger,
            ))

        # Detect removed guards on existing triggers
        for trigger in set(old_triggers) & set(new_triggers):
            old_config = old_triggers[trigger] or {}
            new_config = new_triggers[trigger] or {}
            if not isinstance(old_config, dict) or not isinstance(new_config, dict):
                continue

            for guard in ("branches", "branches-ignore", "paths", "paths-ignore", "types"):
                if guard in old_config and guard not in new_config:
                    changes.append(TrustSurfaceChange(
                        category="trigger_removed_guard",
                        severity=Severity.MEDIUM,
                        description=f"Trigger filter removed: {trigger}.{guard}",
                        file=cf.path,
                        detail=f"Was: {old_config[guard]}",
                    ))

        return changes

    def _diff_secrets(self, cf: ChangedFile) -> list[TrustSurfaceChange]:
        changes = []
        old_secrets = _extract_secret_refs(cf.old_content)
        new_secrets = _extract_secret_refs(cf.new_content)

        for secret in sorted(new_secrets - old_secrets):
            changes.append(TrustSurfaceChange(
                category="new_secret_ref",
                severity=Severity.MEDIUM,
                description=f"New secret reference: secrets.{secret}",
                file=cf.path,
                detail=f"secrets.{secret}",
            ))

        return changes

    def _diff_environments(self, cf: ChangedFile, old: dict, new: dict) -> list[TrustSurfaceChange]:
        changes = []
        old_envs = _extract_environments(old)
        new_envs = _extract_environments(new)

        for job_name in set(old_envs) & set(new_envs):
            if old_envs[job_name] is not None and new_envs[job_name] is None:
                changes.append(TrustSurfaceChange(
                    category="new_environment",
                    severity=Severity.HIGH,
                    description=f"Environment protection removed from job: {job_name}",
                    file=cf.path,
                    detail=f"Was: environment '{old_envs[job_name]}'",
                ))

        return changes

    def _diff_scripts(self, cf: ChangedFile, old: dict, new: dict) -> list[TrustSurfaceChange]:
        changes = []
        old_blocks = _extract_run_blocks(old)
        new_blocks = _extract_run_blocks(new)

        for key, new_script in new_blocks.items():
            old_script = old_blocks.get(key)
            if old_script is None:
                changes.append(TrustSurfaceChange(
                    category="script_change",
                    severity=Severity.MEDIUM,
                    description=f"New run block added: {key}",
                    file=cf.path,
                    detail=new_script[:200],
                ))
            elif old_script != new_script:
                changes.append(TrustSurfaceChange(
                    category="script_change",
                    severity=Severity.MEDIUM,
                    description=f"Run block modified: {key}",
                    file=cf.path,
                    detail=new_script[:200],
                ))

        return changes

    def _compute_risk_delta(self, changes: list[TrustSurfaceChange]) -> int:
        weights = {
            Severity.CRITICAL: 30,
            Severity.HIGH: 15,
            Severity.MEDIUM: 7,
            Severity.LOW: -3,
        }
        delta = sum(weights.get(c.severity, 0) for c in changes)
        return max(-100, min(100, delta))

    def _build_summary(self, changes: list[TrustSurfaceChange], risk_delta: int) -> str:
        if not changes:
            return "No trust surface changes detected in workflow files."

        by_severity = {}
        for c in changes:
            by_severity[c.severity.value] = by_severity.get(c.severity.value, 0) + 1

        parts = [f"{count} {sev}" for sev, count in sorted(
            by_severity.items(),
            key=lambda x: Severity(x[0]).rank,
            reverse=True,
        )]
        direction = "riskier" if risk_delta > 0 else "safer" if risk_delta < 0 else "neutral"
        return f"{len(changes)} trust surface change(s) ({', '.join(parts)}). Risk delta: {risk_delta:+d} ({direction})"


def format_pr_comment(report: DiffReport) -> str:
    severity_emoji = {
        Severity.CRITICAL: "\U0001f534",
        Severity.HIGH: "\U0001f7e0",
        Severity.MEDIUM: "\U0001f7e1",
        Severity.LOW: "⚪",
    }

    lines = ["## Tremor: Trust Surface Diff", ""]

    if not report.changes:
        lines.append("No security-relevant changes detected in workflow files.")
        return "\n".join(lines)

    lines.append(f"**{report.summary}**")
    lines.append("")
    lines.append("| Severity | Category | File | Description |")
    lines.append("|----------|----------|------|-------------|")

    for change in report.changes:
        emoji = severity_emoji.get(change.severity, "")
        category = change.category.replace("_", " ")
        file_short = change.file.split("/")[-1]
        desc = change.description
        lines.append(f"| {emoji} {change.severity.value} | {category} | `{file_short}` | {desc} |")

    lines.append("")
    lines.append("### Details")
    lines.append("")

    for i, change in enumerate(report.changes, 1):
        emoji = severity_emoji.get(change.severity, "")
        lines.append(f"{i}. {emoji} **{change.description}**")
        lines.append(f"   - File: `{change.file}`")
        lines.append(f"   - Detail: {change.detail}")
        lines.append("")

    lines.append(f"**Risk delta: {report.risk_delta:+d}/100**")
    lines.append("")

    if report.risk_delta >= 30:
        lines.append("> ⚠️ This PR significantly expands the trust surface of CI/CD workflows. "
                     "Careful review recommended.")
    elif report.risk_delta >= 15:
        lines.append("> ℹ️ Moderate trust surface expansion. Review the changes above.")

    return "\n".join(lines)
