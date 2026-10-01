"""Rule: debug-mode — debug switches left on outside a laptop."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from ..findings import Severity
from .astutils import dotted_name, is_constant, keyword_value
from .base import LANGUAGES, Match, Rule, RuleOptions, TextDetector, TreeDetector
from .textutils import LinePattern, iter_matches

__all__ = ["debug_mode"]

_RULE_ID = "debug-mode"

#: Call names that start a development server with its debugger attached.
_FLASK_RUN_METHODS = frozenset({"run", "runserver", "runserver_plus"})

#: Upper-cased variable names that switch a debug mode on when set to ``True``.
_GENERIC_DEBUG_NAMES = frozenset({"FLASK_DEBUG", "DEBUG_MODE", "TDEBUG", "DJANGO_DEBUG"})

#: Upper-cased environment variables whose value names the deployment stage.
_ENV_DEBUG_NAMES = frozenset({"FLASK_ENV", "APP_ENV", "ENVIRONMENT"})

#: Environment values that mean "running in development".
_DEV_ENVIRONMENTS = frozenset({"development", "dev", "debug"})

MESSAGE_FLASK = (
    "The Flask app starts with debug=True. The debugger can run arbitrary Python on a "
    "malformed request, so this exposes the server to remote code execution."
)
MESSAGE_DJANGO = (
    "Django runs with DEBUG=True. That returns full tracebacks and settings in error "
    "pages, and turns off the template sandbox."
)
MESSAGE_GENERIC = (
    "A debug flag is enabled here ({what}), which usually leaks stack traces, settings "
    "or internal details in production."
)

FIX_FLASK = (
    "Read the flag from the environment and default it off: "
    'app.run(debug=os.environ.get("FLASK_DEBUG") == "1"), and never enable it on a '
    "publicly reachable server."
)
FIX_DJANGO = "Set DEBUG = False in settings.py and let DEBUG come from the environment."
FIX_GENERIC = "Default this flag to False and enable it only in local development."


def _assigned_name(node: ast.expr) -> str | None:
    """The variable assigned to by a target node, if it is a plain name."""
    return node.id if isinstance(node, ast.Name) else None


def _string_value(node: ast.expr) -> str | None:
    """The literal string assigned to by a node, if any."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _detect_python(tree: ast.AST, source: str, options: RuleOptions) -> Iterator[Match]:
    del options
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = dotted_name(node.func) or ""
            method = func.rsplit(".", 1)[-1]
            debug_kw = keyword_value(node, "debug")
            if method in _FLASK_RUN_METHODS and is_constant(debug_kw, True):
                yield Match(
                    line=node.lineno,
                    col=node.col_offset + 1,
                    message=MESSAGE_FLASK,
                    fix=FIX_FLASK,
                    data={"framework": "flask"},
                )
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            target = node.targets[0] if isinstance(node, ast.Assign) else node.target
            value = node.value
            name = _assigned_name(target)
            if name is None or value is None:
                continue
            upper = name.upper()
            if upper == "DEBUG" and is_constant(value, True):
                yield Match(
                    line=getattr(node, "lineno", 1),
                    col=getattr(node, "col_offset", 0) + 1,
                    message=MESSAGE_DJANGO,
                    fix=FIX_DJANGO,
                    data={"framework": "django"},
                )
            elif upper in _GENERIC_DEBUG_NAMES and is_constant(value, True):
                yield Match(
                    line=getattr(node, "lineno", 1),
                    col=getattr(node, "col_offset", 0) + 1,
                    message=MESSAGE_GENERIC.format(what=f"{name} = True"),
                    fix=FIX_GENERIC,
                    data={"framework": name},
                )
            elif upper in _ENV_DEBUG_NAMES:
                literal = _string_value(value)
                if literal and literal.lower() in _DEV_ENVIRONMENTS:
                    yield Match(
                        line=getattr(node, "lineno", 1),
                        col=getattr(node, "col_offset", 0) + 1,
                        message=MESSAGE_GENERIC.format(what=f'{name} = "{literal}"'),
                        fix='Set the environment to "production" for deployed builds.',
                        data={"framework": name},
                    )


_JS_DEBUG = re.compile(
    r"(?i)\b(?:NODE_ENV\s*[:=]\s*['\"]development['\"]|DEBUG\s*[:=]\s*true|"
    r"debug\s*:\s*true|app\.run\s*\([^)]*debug\s*[:=]\s*true)"
)


def _detect_javascript(source: str, options: RuleOptions) -> Iterator[Match]:
    del options
    patterns = [
        LinePattern(
            _JS_DEBUG,
            "JavaScript enables a debug mode here ({match}); it can leak stack traces "
            "and internal state.",
            FIX_GENERIC,
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


def _detect_config(source: str, options: RuleOptions) -> Iterator[Match]:
    del options
    patterns = [
        LinePattern(
            re.compile(
                r"(?i)\b(?P<key>DEBUG|FLASK_DEBUG|DEBUG_MODE|TDEBUG|NODE_ENV|ENV)\s*[:=]\s*"
                r"(?P<value>true|['\"]?(?:development|dev)['\"]?)"
            ),
            "Configuration sets {key} to {value}, which enables a debug mode.",
            'Set {key} to false (or "production") in deployed configuration.',
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


debug_mode = Rule(
    id=_RULE_ID,
    title="Debug mode enabled",
    severity=Severity.MEDIUM,
    languages=LANGUAGES,
    summary=(
        "A framework runs with debugging on, exposing tracebacks and often an interactive console."
    ),
    detectors={
        "python": TreeDetector(_detect_python),
        "javascript": TextDetector(_detect_javascript),
        "config": TextDetector(_detect_config),
    },
    cwe="CWE-489",
    references=(
        "https://cwe.mitre.org/data/definitions/489.html",
        "https://flask.palletsprojects.com/en/stable/debugging/",
    ),
)
