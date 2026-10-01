"""Rule: hardcoded-secret — credentials written straight into the source."""

from __future__ import annotations

import ast
import math
import re
from collections import Counter
from collections.abc import Iterator

from ..findings import Severity
from .base import LANGUAGES, Match, Rule, RuleOptions, TextDetector, TreeDetector
from .textutils import LinePattern, iter_matches

__all__ = ["hardcoded_secret"]

_RULE_ID = "hardcoded-secret"

#: Words that make an identifier a credential no matter what the value looks like.
SECRET_NAME_RE = re.compile(
    r"(?i)("
    r"api[_-]?key|apikey|secret[_-]?key|secret|token|access[_-]?key|auth[_-]?token|"
    r"password|passwd|pwd|credentials?|private[_-]?key|encryption[_-]?key|"
    r"client[_-]?secret|session[_-]?key|signing[_-]?key|auth|bearer|salt"
    r")"
)

#: Recognisable credential formats. Checked regardless of the variable name.
SECRET_SHAPES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[0-9A-Za-z-]{10,}")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("Stripe secret key", re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{16,}")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("JSON web token", re.compile(r"\beyJ[0-9A-Za-z_-]{8,}\.[0-9A-Za-z_-]{8,}\.")),
    ("bearer token", re.compile(r"(?i)\bbearer\s+[0-9A-Za-z._~+/-]{20,}={0,2}")),
)

#: Markers that mean "documentation or scaffolding", not a live credential.
#: These are deliberately distinctive: short generic words such as "abcdef"
#: would match inside a genuine base64 token and hide a real leak.
PLACEHOLDER_MARKERS = (
    "your_",
    "your-",
    "yourapi",
    "example",
    "placeholder",
    "changeme",
    "change_me",
    "change-me",
    "replace",
    "insert",
    "sample",
    "dummy",
    "fake",
    "notreal",
    "not_a_real",
    "not-a-real",
    "dont_use",
    "do_not_use",
    "xxxxxxxx",
    "todo",
    "fixme",
    "redacted",
)

#: Exact values that are never credentials on their own.
PLACEHOLDER_VALUES = frozenset(
    {
        "none",
        "null",
        "nil",
        "true",
        "false",
        "test",
        "changeme",
        "password",
        "secret",
        "token",
        "apikey",
        "api_key",
        "api-key",
        "hunter2",
        "default",
        "unset",
    }
)

#: Sample keys published in vendor documentation. They match real token formats
#: but are safe to commit, so they are never reported.
DOCUMENTED_EXAMPLES = frozenset(
    {
        "AKIAIOSFODNN7EXAMPLE",
        "AKIAI44QH8DHBEXAMPLE",
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    }
)

#: Values that are too short or too uniform to be a real credential.
MIN_SECRET_LENGTH = 12
MIN_ENTROPY_BITS = 2.5
MIN_DISTINCT_CHARS = 6

MESSAGE = "This file contains a hardcoded credential: {name} looks like a {shape}."
FIX = (
    "Remove the value and read it from the environment "
    '(os.environ["YOUR_API_KEY_HERE"]) or a secret manager at runtime, then rotate '
    "the exposed key because anyone with this repository can use it."
)


def _is_placeholder(value: str) -> bool:
    """Whether *value* is obviously scaffolding rather than a live credential."""
    stripped = value.strip()
    if not stripped:
        return True
    if stripped in DOCUMENTED_EXAMPLES:
        return True
    lowered = stripped.lower()
    if lowered in PLACEHOLDER_VALUES:
        return True
    if any(marker in lowered for marker in PLACEHOLDER_MARKERS):
        return True
    if stripped.startswith(("<", "{{", "${", "%", "os.environ", "os.getenv", "process.env")):
        return True
    return len(set(stripped)) < MIN_DISTINCT_CHARS


def _entropy_bits(value: str) -> float:
    """Shannon entropy of *value*, in bits per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def _looks_random(value: str) -> bool:
    """Whether *value* has the character mix of a generated secret."""
    return (
        len(value) >= MIN_SECRET_LENGTH
        and len(set(value)) >= MIN_DISTINCT_CHARS
        and _entropy_bits(value) >= MIN_ENTROPY_BITS
    )


def _match_shape(value: str) -> str | None:
    """Name of the credential shape *value* matches, if any."""
    for name, pattern in SECRET_SHAPES:
        if pattern.search(value):
            return name
    return None


def _secret_report(value: str, name: str) -> tuple[str, str] | None:
    """Return ``(shape, message)`` when *value* is a credential, else ``None``.

    Two ways to qualify:

    * the value matches a known credential format (AWS, Stripe, GitHub, ...) —
      a recognised token is reported even when it also looks repetitive, since
      base64 padding and vendor prefixes can trip the generic filters;
    * the name is credential-ish and the value looks randomly generated.
    """
    stripped = value.strip()
    if not stripped or stripped in DOCUMENTED_EXAMPLES:
        return None
    shape = _match_shape(stripped)
    if shape is not None:
        return shape, MESSAGE.format(name=name, shape=shape)
    if SECRET_NAME_RE.search(name) and not _is_placeholder(stripped) and _looks_random(stripped):
        return "random string", MESSAGE.format(name=name, shape="random string")
    return None


# --------------------------------------------------------------------------- #
# Python
# --------------------------------------------------------------------------- #


def _target_names(node: ast.expr) -> list[str]:
    """Names assigned to by *node*; tuple targets expand to their elements."""
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.Tuple, ast.List)):
        names: list[str] = []
        for element in node.elts:
            names.extend(_target_names(element))
        return names
    if isinstance(node, ast.Attribute):
        return [node.attr]
    return []


def _string_literals(node: ast.expr) -> Iterator[str]:
    """String literals assigned by *node*."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        yield node.value
        return
    if isinstance(node, ast.JoinedStr):
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                yield part.value


def _detect_python(tree: ast.AST, source: str, options: RuleOptions) -> Iterator[Match]:
    del source
    skip_names = {str(item).lower() for item in options.get("ignore_names", [])}
    seen: set[tuple[int, int, str]] = set()
    for node in ast.walk(tree):
        pairs: list[tuple[list[str], ast.expr]] = []
        if isinstance(node, ast.Assign):
            value = node.value
            pairs = [(_target_names(target), value) for target in node.targets]
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            pairs = [([node.target.id] if isinstance(node.target, ast.Name) else [], node.value)]
        if not pairs:
            continue
        line = getattr(node, "lineno", 1)
        col = getattr(node, "col_offset", 0)
        for names, value in pairs:
            literals = list(_string_literals(value))
            if not literals:
                continue
            for name in names:
                if not name or name.lower() in skip_names:
                    continue
                for literal in literals:
                    report = _secret_report(literal, name)
                    if report is None:
                        continue
                    key = (line, col, literal)
                    if key in seen:
                        continue
                    seen.add(key)
                    yield Match(
                        line=line,
                        col=col + 1,
                        message=report[1],
                        fix=FIX,
                        data={"variable": name, "shape": report[0]},
                    )


# --------------------------------------------------------------------------- #
# Configuration files (JSON / YAML / TOML / .env / ini)
# --------------------------------------------------------------------------- #

#: ``key: value`` / ``key = value`` / ``"key": "value"`` with a secret-ish key.
_CONFIG_KEY = (
    r"(?P<key>[\"']?[0-9A-Za-z_.\-\[\]]*"
    r"(?:api[_-]?key|apikey|secret[_-]?key|secret|token|password|passwd|pwd|"
    r"credentials?|private[_-]?key|client[_-]?secret|access[_-]?key|auth|bearer)"
    r"[0-9A-Za-z_.\-\[\]]*[\"']?)"
)
_CONFIG_PAIR_RE = re.compile(
    _CONFIG_KEY + r"""\s*[:=]\s*(?P<quote>["']?)(?P<value>[^"'\n#]{6,})(?P=quote)""",
    re.IGNORECASE,
)


def _detect_config(source: str, options: RuleOptions) -> Iterator[Match]:
    del options
    patterns = [
        LinePattern(
            _CONFIG_PAIR_RE,
            "Configuration entry '{key}' holds a hardcoded {shape}.",
            "Move the value into an environment variable or secret manager and "
            "rotate the exposed credential.",
        ),
    ]
    seen: set[tuple[int, str]] = set()
    for spec in iter_matches(source, patterns):
        key = spec.data.get("key", "").strip("\"'")
        value = spec.data.get("value", "").strip()
        report = _secret_report(value, key)
        if report is None:
            continue
        dedupe = (spec.line, key.lower())
        if dedupe in seen:
            continue
        seen.add(dedupe)
        yield Match(
            line=spec.line,
            col=spec.col,
            message=report[1],
            fix=FIX,
            data={"variable": key, "shape": report[0]},
        )


# --------------------------------------------------------------------------- #
# JavaScript / TypeScript
# --------------------------------------------------------------------------- #

_JS_KEY = (
    r"(?P<key>[0-9A-Za-z_$]*(?:api[_-]?key|apikey|secret|token|password|passwd|pwd|"
    r"credentials?|private[_-]?key|client[_-]?secret|access[_-]?key|auth|bearer)[0-9A-Za-z_$]*)"
)
_JS_ASSIGN_RE = re.compile(
    _JS_KEY + r"""\s*[:=]\s*(?P<quote>["'`])(?P<value>[^"'`\n]{8,})(?P=quote)""",
    re.IGNORECASE,
)


def _detect_javascript(source: str, options: RuleOptions) -> Iterator[Match]:
    del options
    patterns = [
        LinePattern(
            _JS_ASSIGN_RE,
            "JavaScript value assigned to '{key}' is a hardcoded {shape}.",
            "Read the value from process.env on the server or a secrets store, "
            "and rotate the exposed credential.",
        ),
    ]
    seen: set[tuple[int, str]] = set()
    for spec in iter_matches(source, patterns):
        key = spec.data.get("key", "")
        report = _secret_report(spec.data.get("value", ""), key)
        if report is None:
            continue
        dedupe = (spec.line, key.lower())
        if dedupe in seen:
            continue
        seen.add(dedupe)
        yield Match(
            line=spec.line,
            col=spec.col,
            message=report[1],
            fix=FIX,
            data={"variable": key, "shape": report[0]},
        )


hardcoded_secret = Rule(
    id=_RULE_ID,
    title="Hardcoded secret in source code",
    severity=Severity.CRITICAL,
    languages=LANGUAGES,
    summary="A string shaped like a live API key, token or private key is stored in the file.",
    detectors={
        "python": TreeDetector(_detect_python),
        "javascript": TextDetector(_detect_javascript),
        "config": TextDetector(_detect_config),
    },
    cwe="CWE-798",
    references=(
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://owasp.org/www-project-top-ten/A07-2021-Identification-and-Authentication-Failures/",
    ),
)
