"""Configuration loading and defaults."""

from pathlib import Path
from typing import Any


DEFAULT_CONFIG = {
    "workflow_paths": [".github/workflows"],
    "severity_threshold": "medium",
    "checks": {
        "unpinned_actions": True,
        "dangerous_triggers": True,
        "script_injection": True,
        "excessive_permissions": True,
        "secret_exposure": True,
        "mutable_tags": True,
        "untrusted_pr_checkout": True,
    },
    "allow": {
        "actions": [],
        "permissions": [],
        "triggers": [],
    },
}


def load_config(config_path: str) -> dict[str, Any]:
    path = Path(config_path)
    if not path.exists():
        return DEFAULT_CONFIG.copy()

    import yaml  # noqa: delayed import — only if config exists

    with open(path) as f:
        user_config = yaml.safe_load(f) or {}

    merged = DEFAULT_CONFIG.copy()
    for key, value in user_config.items():
        if isinstance(value, dict) and key in merged and isinstance(merged[key], dict):
            merged[key] = {**merged[key], **value}
        else:
            merged[key] = value

    return merged
