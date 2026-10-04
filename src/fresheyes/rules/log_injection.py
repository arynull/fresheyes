"""Log injection through untrusted input written to a log call."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from ..findings import Severity
from .astutils import dotted_name, iter_calls, keyword_value
from .base import Match, Rule, RuleOptions, TextDetector, TreeDetector
from .textutils import LinePattern, iter_matches

_MESSAGE = (
    "This code writes a value that may come from user input into a log message. "
    "An attacker who controls that value can inject newline characters to forge "
    "fake log entries or hide their real trail."
)
_FIX = (
    "Treat logged values as untrusted output: strip or encode newlines and control "
    "characters before logging — for example `value.replace(chr(10), ' ')`, or log "
    "`repr(value)` — or use structured logging that escapes values."
)

_LEVELS = frozenset({"debug", "info", "warning", "warn", "error", "exception", "critical"})

_UNTRUSTED_RE = re.compile(
    r"^(request|req|args|form|query|params|headers|cookies|body|payload|user_input|"
    r"form_data|query_params|search|username|user_name|email)$",
    re.IGNORECASE,
)

_JS_NAME = (
    r"(?:req|request|query|params|body|headers|cookies|form|userInput|user_input|searchParams)"
)

_JS_PATTERNS = (
    LinePattern(
        regex=re.compile(
            rf"console\.(?:log|info|warn|error|debug)\s*\([^)]*?\$\{{[^}}]*\b{_JS_NAME}\b[^}}]*\}}",
            re.DOTALL,
        ),
        message=_MESSAGE,
        fix=_FIX,
    ),
    LinePattern(
        regex=re.compile(
            rf"console\.(?:log|info|warn|error|debug)\s*\([^)]*(?:\+[^)]*\b{_JS_NAME}\b|\b{_JS_NAME}\b[^)]*\+)",
            re.DOTALL,
        ),
        message=_MESSAGE,
        fix=_FIX,
    ),
)


def _is_logger_call(node: ast.Call) -> bool:
    func = node.func
    if isinstance(func, ast.Attribute):
        if func.attr not in _LEVELS:
            return False
        recv = func.value
        if isinstance(recv, ast.Name):
            if recv.id == "logging":
                return True
            low = recv.id.lower()
            return low.endswith("log") or low.endswith("logger")
        dotted = dotted_name(recv)
        if dotted is None:
            return False
        last = dotted.split(".")[-1]
        if last == "logging":
            return True
        low = last.lower()
        return low.endswith("log") or low.endswith("logger")
    if isinstance(func, ast.Name):
        if func.id == "print":
            return False
        return func.id in _LEVELS
    return False


def _contains_untrusted(node: ast.AST) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            if _UNTRUSTED_RE.match(child.id):
                return True
        elif isinstance(child, ast.Attribute):
            dotted = dotted_name(child)
            if dotted is not None and _UNTRUSTED_RE.match(dotted.split(".")[0]):
                return True
    return False


def _check_python(tree: ast.AST, source: str, options: RuleOptions) -> Iterator[Match]:
    for node in iter_calls(tree):
        if not _is_logger_call(node):
            continue
        targets = list(node.args)
        msg_value = keyword_value(node, "msg")
        if msg_value is not None:
            targets.append(msg_value)
        if not any(_contains_untrusted(arg) for arg in targets):
            continue
        yield Match(line=node.lineno, col=node.col_offset + 1, message=_MESSAGE, fix=_FIX)


def _check_js(source: str, options: RuleOptions) -> Iterator[Match]:
    seen: set[tuple[int, int]] = set()
    for spec in iter_matches(source, _JS_PATTERNS):
        key = (spec.line, spec.col)
        if key in seen:
            continue
        seen.add(key)
        yield Match(line=spec.line, col=spec.col, message=spec.message, fix=spec.fix)


log_injection = Rule(
    id="log-injection",
    title="Untrusted input passed to a log call",
    severity=Severity.MEDIUM,
    languages=("python", "javascript"),
    summary="Untrusted input written to a log message allows log forging via newlines.",
    detectors={
        "python": TreeDetector(_check_python),
        "javascript": TextDetector(_check_js),
    },
    cwe="CWE-117",
    references=("CWE-117",),
)
