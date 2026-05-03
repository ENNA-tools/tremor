"""Tremor check modules."""

from tremor.checks.pinning import UnpinnedActionCheck, MutableTagCheck
from tremor.checks.triggers import DangerousTriggerCheck, UntrustedPRCheckoutCheck
from tremor.checks.injection import ScriptInjectionCheck
from tremor.checks.permissions import ExcessivePermissionsCheck
from tremor.checks.secrets import SecretExposureCheck

ALL_CHECKS = [
    UnpinnedActionCheck,
    MutableTagCheck,
    DangerousTriggerCheck,
    UntrustedPRCheckoutCheck,
    ScriptInjectionCheck,
    ExcessivePermissionsCheck,
    SecretExposureCheck,
]
