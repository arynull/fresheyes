"""The rule registry: every rule fresheyes knows about, in one place."""

from __future__ import annotations

from ..findings import Severity
from .base import Rule
from .client_side_secret import client_side_secret
from .command_injection import command_injection
from .cors_wildcard import cors_wildcard
from .debug_mode import debug_mode
from .eval_exec import eval_exec
from .hardcoded_secret import hardcoded_secret
from .insecure_deserialization import insecure_deserialization
from .insecure_random import insecure_random
from .jwt_no_verify import jwt_no_verify
from .log_injection import log_injection
from .sql_injection import sql_injection
from .template_injection import template_injection
from .tls_no_verify import tls_no_verify
from .weak_crypto import weak_crypto

__all__ = ["ALL_RULES", "RULES_BY_ID", "get_rule", "rule_ids"]

#: Every rule in v0.1.0, ordered by severity then id.
ALL_RULES: tuple[Rule, ...] = (
    hardcoded_secret,
    jwt_no_verify,
    sql_injection,
    command_injection,
    insecure_deserialization,
    tls_no_verify,
    template_injection,
    client_side_secret,
    insecure_random,
    log_injection,
    weak_crypto,
    debug_mode,
    cors_wildcard,
    eval_exec,
)

RULES_BY_ID: dict[str, Rule] = {rule.id: rule for rule in ALL_RULES}


def get_rule(rule_id: str) -> Rule | None:
    """The rule with *rule_id*, or ``None`` when it is not registered."""
    return RULES_BY_ID.get(rule_id)


def rule_ids() -> tuple[str, ...]:
    """All registered rule ids."""
    return tuple(rule.id for rule in ALL_RULES)


def by_severity() -> tuple[tuple[Severity, tuple[Rule, ...]], ...]:
    """Rules grouped by severity, most urgent first."""
    return tuple(
        (
            severity,
            tuple(rule for rule in ALL_RULES if rule.severity is severity),
        )
        for severity in Severity
    )
