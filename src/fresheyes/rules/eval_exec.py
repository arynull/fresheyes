"""Rule: eval-exec — running strings as code."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from ..findings import Severity
from .astutils import dotted_name
from .base import LANGUAGES, Match, Rule, RuleOptions, TextDetector, TreeDetector
from .textutils import LinePattern, iter_matches

__all__ = ["eval_exec"]

_RULE_ID = "eval-exec"

#: Builtins that turn a string into running code.
DANGEROUS_BUILTINS = frozenset({"eval", "exec", "compile"})

MESSAGE = (
    "This code runs text as a Python program ({call}). If any part of that text comes "
    "from a user, file or network, it is arbitrary code execution."
)
MESSAGE_ATTR = (
    "This code runs text as a Python program ({call}), which executes arbitrary code "
    "coming from that object."
)
MESSAGE_COMPILE = (
    "This code compiles text into runnable code ({call}). Anything built from input "
    "becomes an executable program."
)

FIX = (
    "Replace the dynamic code with an explicit dispatch table keyed by a fixed set of "
    'names: actions = {"greet": greet, "sum": add}; return actions[command](arg). '
    "For expressions, use ast.literal_eval for data literals or json.loads for JSON."
)


def _is_literal(node: ast.AST) -> bool:
    """Whether *node* is a constant the author wrote inline."""
    return isinstance(node, ast.Constant)


def _dynamic_argument(node: ast.Call) -> ast.expr | None:
    """The argument of *node* that is built at runtime, if any."""
    if not node.args:
        return None
    argument = node.args[0]
    if _is_literal(argument):
        return None
    return argument


def _detect_python(tree: ast.AST, source: str, options: RuleOptions) -> Iterator[Match]:
    del source, options
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = dotted_name(node.func) or (node.func.id if isinstance(node.func, ast.Name) else "")
        method = name.rsplit(".", 1)[-1]
        if method not in DANGEROUS_BUILTINS:
            continue
        argument = _dynamic_argument(node)
        if argument is None:
            continue
        if method == "compile":
            yield Match(
                line=node.lineno,
                col=node.col_offset + 1,
                message=MESSAGE_COMPILE.format(call=name or "compile"),
                fix=FIX,
                data={"call": name},
            )
        elif "." in name:
            yield Match(
                line=node.lineno,
                col=node.col_offset + 1,
                message=MESSAGE_ATTR.format(call=name),
                fix=FIX,
                data={"call": name},
            )
        else:
            yield Match(
                line=node.lineno,
                col=node.col_offset + 1,
                message=MESSAGE.format(call=name),
                fix=FIX,
                data={"call": name},
            )


_JS_EVAL = re.compile(
    r"(?i)\b(?P<call>eval|Function)\s*\(\s*"
    r"(?P<arg>`[^`]*\$\{[^}]*\}[^`]*`"
    r"|['\"][^'\"]*['\"]\s*\+\s*[^,)]*"
    r"|[a-z_$][\w$.\[\]\"'() ]*)"
)
_JS_INDICATOR = re.compile(r"(?i)(\$\{|\+\s*[a-z_$]|request|req\.|body|query|params|input|user)")


def _detect_javascript(source: str, options: RuleOptions) -> Iterator[Match]:
    del options
    patterns = [LinePattern(_JS_EVAL, "", FIX)]
    for spec in iter_matches(source, patterns):
        argument = spec.data.get("arg", "")
        if not _JS_INDICATOR.search(argument):
            continue
        yield Match(
            line=spec.line,
            col=spec.col,
            message=MESSAGE.format(call=spec.data.get("call", "eval")),
            fix=FIX,
            data=dict(spec.data),
        )


def _detect_config(source: str, options: RuleOptions) -> Iterator[Match]:
    del options
    patterns = [
        LinePattern(
            re.compile(
                r"(?i)\b(?P<key>allow_eval|enable_eval|eval_allowed)\s*[:=]\s*(?P<value>true|1)"
            ),
            "Configuration {key} is set to {value}, permitting evaluation of dynamic code.",
            "Remove the setting and validate input against an explicit allow-list instead.",
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


eval_exec = Rule(
    id=_RULE_ID,
    title="Dynamic code execution",
    severity=Severity.MEDIUM,
    languages=LANGUAGES,
    summary=(
        "A string is executed as a program, so any influence over that string is code execution."
    ),
    detectors={
        "python": TreeDetector(_detect_python),
        "javascript": TextDetector(_detect_javascript),
        "config": TextDetector(_detect_config),
    },
    cwe="CWE-95",
    references=(
        "https://cwe.mitre.org/data/definitions/95.html",
        "https://owasp.org/www-community/attacks/Code_Injection",
    ),
)
