"""Inline suppression comments: ``# fresheyes: ignore[rule-id] ...``."""

from __future__ import annotations

import re

__all__ = ["IGNORE_MARKER", "parse_suppressions", "suppressed"]

#: Text that marks a line as suppressed, with an optional rule list and reason.
IGNORE_MARKER = "fresheyes: ignore"

_PATTERN = re.compile(r"(^|\s)#\s*fresheyes:\s*ignore(?:\[([^\]]*)\])?")


def parse_suppressions(source: str) -> dict[int, frozenset[str]]:
    """Map line numbers to the rule ids suppressed on that line.

    An empty rule list (``# fresheyes: ignore``) suppresses every rule.
    A standalone comment also covers the following line, so a finding can be
    pushed above the code it applies to. Anything after the bracket — a reason
    such as ``-- server-side only`` — is accepted and ignored.
    """
    table: dict[int, frozenset[str]] = {}
    for lineno, line in enumerate(source.splitlines(), start=1):
        match = _PATTERN.search(line)
        if match is None:
            continue
        listed = match.group(2)
        parts = re.split(r"[,\s]+", listed) if listed else []
        rule_ids = frozenset(part for part in parts if part) if listed else frozenset({"*"})
        table[lineno] = rule_ids
        if line.lstrip().startswith("#"):
            table[lineno + 1] = rule_ids
    return table


def suppressed(table: dict[int, frozenset[str]], line: int, rule_id: str) -> bool:
    """Return whether *rule_id* is suppressed at *line*."""
    rule_ids = table.get(line)
    if not rule_ids:
        return False
    return "*" in rule_ids or rule_id in rule_ids
