"""Rendering results for humans and for machines."""

from __future__ import annotations

import json
from typing import Any

from .config import Config
from .engine import ScanResult
from .findings import SEVERITY_ORDER, Severity, counts_by_severity

__all__ = ["render_json", "render_human", "render_rules_json", "render_rules_human"]

_SEVERITY_LABEL = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH    ",
    Severity.MEDIUM: "MEDIUM  ",
    Severity.LOW: "LOW     ",
}


def _plural(count: int, word: str) -> str:
    return f"{count} {word}" if count == 1 else f"{count} {word}s"


def render_human(result: ScanResult, config: Config) -> str:
    """A readable report: grouped findings with fixes, then a summary."""
    lines: list[str] = []
    findings = result.findings

    if not findings:
        lines.append("No findings.")
        lines.append("")
        lines.append(
            f"Scanned {_plural(result.files_scanned, 'file')} "
            f"({result.files_skipped} skipped) in {result.duration_s:.2f}s."
        )
        return "\n".join(lines)

    current_path: str | None = None
    for finding in findings:
        if finding.path != current_path:
            current_path = finding.path
            lines.append("")
            lines.append(f"{current_path}")
        lines.append(
            f"  {_SEVERITY_LABEL[finding.severity]}  {finding.location}  "
            f"{finding.message}  [{finding.rule_id}]"
        )
        if finding.fix:
            lines.append(f"            fix: {finding.fix}")

    counts = counts_by_severity(findings)
    breakdown = ", ".join(
        f"{counts[severity.value]} {severity.value}"
        for severity in SEVERITY_ORDER
        if counts[severity.value]
    )
    lines.append("")
    lines.append(
        f"Found {_plural(counts['total'], 'issue')} ({breakdown}) "
        f"in {_plural(result.files_scanned, 'file')} in {result.duration_s:.2f}s."
    )
    threshold = config.fail_on_severity
    blocking = [finding for finding in findings if finding.severity.rank >= threshold.rank]
    if blocking:
        lines.append(f"Exit 1: {len(blocking)} finding(s) at or above {threshold}.")
    else:
        lines.append(f"No findings at or above {threshold}; exiting 0.")
    return "\n".join(lines)


def render_json(result: ScanResult, config: Config) -> str:
    """Machine-readable report, stable across versions by documented keys."""
    counts = counts_by_severity(result.findings)
    threshold = config.fail_on_severity
    blocking = [finding for finding in result.findings if finding.severity.rank >= threshold.rank]
    payload: dict[str, Any] = {
        "version": _version(),
        "summary": {
            "total": counts["total"],
            "by_severity": {severity.value: counts[severity.value] for severity in SEVERITY_ORDER},
            "files_scanned": result.files_scanned,
            "files_skipped": result.files_skipped,
            "fail_on_severity": threshold.value,
            "blocking": len(blocking),
            "duration_s": round(result.duration_s, 4),
        },
        "findings": [finding.as_dict() for finding in result.findings],
    }
    if result.parse_errors:
        payload["parse_errors"] = [
            {"path": path, "error": message} for path, message in result.parse_errors
        ]
    return json.dumps(payload, indent=2, sort_keys=False)


def render_rules_human() -> str:
    """A readable catalogue of every rule."""
    from .rules import ALL_RULES

    lines = [f"fresheyes rules ({len(ALL_RULES)} rules)", ""]
    for rule in sorted(ALL_RULES, key=lambda item: (-item.severity.rank, item.id)):
        lines.append(f"  {_SEVERITY_LABEL[rule.severity].strip():<8}  {rule.id}")
        lines.append(f"      {rule.title}")
        detector = rule.detector_kind
        lines.append(f"      languages: {', '.join(rule.languages)}  detector: {detector}")
        lines.append(f"      {rule.summary}")
        if rule.cwe:
            lines.append(f"      cwe: {rule.cwe}")
        lines.append("")
    lines.append("Suppress a finding on a single line with:  # fresheyes: ignore[rule-id]")
    return "\n".join(lines)


def render_rules_json() -> str:
    """Machine-readable rule catalogue."""
    from .rules import ALL_RULES

    ordered = sorted(ALL_RULES, key=lambda item: (-item.severity.rank, item.id))
    payload = {
        "version": _version(),
        "rules": [rule.as_dict() for rule in ordered],
    }
    return json.dumps(payload, indent=2)


def _version() -> str:
    from . import __version__

    return __version__
