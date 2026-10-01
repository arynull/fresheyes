"""Rule: tls-no-verify — certificate or hostname checking turned off."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from ..findings import Severity
from .astutils import dotted_name, is_constant, keyword_value
from .base import LANGUAGES, Match, Rule, RuleOptions, TextDetector, TreeDetector
from .textutils import LinePattern, iter_matches

__all__ = ["tls_no_verify"]

_RULE_ID = "tls-no-verify"

#: Client constructors that accept ``verify=``.
TLS_CLIENTS = frozenset({"get", "post", "put", "delete", "patch", "head", "request", "Session"})

#: Context factories that skip verification when called without arguments.
UNVERIFIED_FACTORIES = frozenset(
    {"ssl._create_unverified_context", "ssl._create_default_https_context"}
)

MESSAGE = (
    "TLS certificate verification is disabled ({what}), so the connection can be "
    "intercepted by anyone on the network."
)
FIX = (
    "Delete the option so verification stays on: use requests.get(url) instead of "
    'requests.get(url, verify=False), pass verify="path/to/ca-bundle.pem" for a private '
    "certificate authority, and use ssl.create_default_context() for raw sockets."
)


def _report(node: ast.AST, what: str, col_offset: int = 0) -> Match:
    return Match(
        line=getattr(node, "lineno", 1),
        col=getattr(node, "col_offset", 0) + 1 + col_offset,
        message=MESSAGE.format(what=what),
        fix=FIX,
        data={"what": what},
    )


def _detect_python(tree: ast.AST, source: str, options: RuleOptions) -> Iterator[Match]:
    del source, options
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = dotted_name(node.func) or (node.func.id if isinstance(node.func, ast.Name) else "")

        if name in UNVERIFIED_FACTORIES:
            yield _report(node, name)
            continue
        if is_constant(keyword_value(node, "verify"), False):
            yield _report(node, f"{name or 'request'}(verify=False)")
            continue
        cert_kw = keyword_value(node, "cert_reqs")
        if isinstance(cert_kw, ast.Attribute) and cert_kw.attr == "CERT_NONE":
            yield _report(node, "ssl context with cert_reqs=CERT_NONE")
            continue
        if is_constant(keyword_value(node, "check_hostname"), False):
            yield _report(node, "hostname checking disabled")
            continue
        verify_mode = keyword_value(node, "verify_mode")
        if isinstance(verify_mode, ast.Attribute) and verify_mode.attr == "CERT_NONE":
            yield _report(node, "ssl context with verify_mode=CERT_NONE")


def _detect_python_attribute(tree: ast.AST, source: str, options: RuleOptions) -> Iterator[Match]:
    """``ctx.verify_mode = ssl.CERT_NONE`` — the attribute form of the same bug."""
    del source, options
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Attribute)
            and node.value.attr == "CERT_NONE"
        ):
            yield _report(node, "ssl.CERT_NONE")


def _python(tree: ast.AST, source: str, options: RuleOptions) -> Iterator[Match]:
    """Both the call form (``verify=False``) and the attribute form (CERT_NONE)."""
    seen: set[tuple[int, int]] = set()
    for detector in (_detect_python, _detect_python_attribute):
        for match in detector(tree, source, options):
            key = (match.line, match.col)
            if key in seen:
                continue
            seen.add(key)
            yield match


_JS_VERIFY_FALSE = re.compile(
    r"(?i)\b(verify|rejectUnauthorized|checkServerIdentity|strictSSL)\s*[:=]\s*"
    r"(false|'none'|\"none\")"
)
_JS_TLS_OFF = re.compile(
    r"(?i)\b(?:rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|"
    r"process\.env\.NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0|strictSSL\s*:\s*false)"
)


def _js_detect(source: str, options: RuleOptions) -> Iterator[Match]:
    del options
    patterns = [
        LinePattern(
            _JS_TLS_OFF,
            "JavaScript disables TLS certificate checks ({match}); traffic can be intercepted.",
            FIX,
        ),
        LinePattern(
            _JS_VERIFY_FALSE,
            "JavaScript sets {match}, which turns off certificate validation.",
            FIX,
        ),
    ]
    seen: set[int] = set()
    for spec in iter_matches(source, patterns):
        if spec.line in seen:
            continue
        seen.add(spec.line)
        yield Match(
            line=spec.line,
            col=spec.col,
            message=spec.message,
            fix=spec.fix,
            data=dict(spec.data),
        )


_CONFIG_TLS = re.compile(
    r"(?i)(?P<key>[\"']?(?:verify|reject[_-]?unauthorized|strict[_-]?ssl|ssl[_-]?verify|tls[_-]?verify)[\"']?)"
    r"\s*[:=]\s*(?P<value>false|'false'|\"false\"|0|'none'|\"none\")"
)


def _config_detect(source: str, options: RuleOptions) -> Iterator[Match]:
    del options
    patterns = [
        LinePattern(
            _CONFIG_TLS,
            "Configuration sets {key} to {value}, disabling certificate validation.",
            FIX,
        ),
    ]
    for spec in iter_matches(source, patterns):
        yield Match(
            line=spec.line,
            col=spec.col,
            message=spec.message,
            fix=spec.fix,
            data=dict(spec.data),
        )


tls_no_verify = Rule(
    id=_RULE_ID,
    title="TLS certificate verification disabled",
    severity=Severity.HIGH,
    languages=LANGUAGES,
    summary="A connection is made without checking the server certificate, defeating TLS.",
    detectors={
        "python": TreeDetector(_python),
        "javascript": TextDetector(_js_detect),
        "config": TextDetector(_config_detect),
    },
    cwe="CWE-295",
    references=(
        "https://cwe.mitre.org/data/definitions/295.html",
        "https://requests.readthedocs.io/en/latest/user/advanced/#ssl-cert-verification",
    ),
)
