"""Client-inlined env vars with credential-ish names read into browser code."""

from __future__ import annotations

import re
from collections.abc import Iterator

from ..findings import Severity
from .base import Match, Rule, RuleOptions, TextDetector
from .textutils import LinePattern, iter_matches

_MESSAGE = (
    "Reading {name} here: NEXT_PUBLIC_* / VITE_* / REACT_APP_* variables are inlined "
    "into the JavaScript sent to browsers at build time, so a credential-ish value is "
    "visible to every visitor — it is not a secret."
)
_FIX = (
    "Keep the credential in a server-only variable (drop the public prefix), read it in "
    "server code or an API route, and pass only safe, derived values to the client."
)

_CRED_RE = re.compile(
    r"(?:^|[_-])(?:api[_-]?key|secret|token|private[_-]?key|password|passwd|pwd|"
    r"client[_-]?secret|auth[_-]?token|bearer|signing[_-]?key|access[_-]?key|"
    r"encryption[_-]?key|key)(?:[_-]|$)",
    re.IGNORECASE,
)

_PUBLIC_PREFIXES = ("NEXT_PUBLIC_", "REACT_APP_", "VITE_")

_DOT = r"process\.env\.(?P<dot>NEXT_PUBLIC_[0-9A-Za-z_]+|REACT_APP_[0-9A-Za-z_]+)"
_BRACKET = (
    r"process\.env\[\s*(?P<q1>['\"])"
    r"(?P<bracket>NEXT_PUBLIC_[0-9A-Za-z_]+|REACT_APP_[0-9A-Za-z_]+)(?P=q1)\s*\]"
)
_VITE_DOT = r"import\.meta\.env\.(?P<vitedot>VITE_[0-9A-Za-z_]+)"
_VITE_BRACKET = (
    r"import\.meta\.env\[\s*(?P<q2>['\"])"
    r"(?P<vitebracket>VITE_[0-9A-Za-z_]+)(?P=q2)\s*\]"
)
_DESTRUCT = (
    r"(?P<destructure>NEXT_PUBLIC_[0-9A-Za-z_]+|REACT_APP_[0-9A-Za-z_]+|VITE_[0-9A-Za-z_]+)"
    r"\b(?=[^}{]*?\}\s*=\s*process\.env\b)"
)

_ENV_RE = re.compile("|".join((_DOT, _BRACKET, _VITE_DOT, _VITE_BRACKET, _DESTRUCT)))

_JS_PATTERNS = (LinePattern(regex=_ENV_RE, message=_MESSAGE, fix=_FIX),)


def _is_credentialish(name: str) -> bool:
    if "publishable" in name.lower():
        return False
    upper = name.upper()
    suffix = ""
    for prefix in _PUBLIC_PREFIXES:
        if upper.startswith(prefix):
            suffix = name[len(prefix) :]
            break
    if not suffix:
        return False
    return bool(_CRED_RE.search(suffix))


def _detect_javascript(source: str, options: RuleOptions) -> Iterator[Match]:
    del options
    seen: set[tuple[int, str]] = set()
    for spec in iter_matches(source, _JS_PATTERNS):
        name = (
            spec.data.get("dot")
            or spec.data.get("bracket")
            or spec.data.get("vitedot")
            or spec.data.get("vitebracket")
            or spec.data.get("destructure")
            or ""
        )
        if not name:
            continue
        if not _is_credentialish(name):
            continue
        key = (spec.line, name.lower())
        if key in seen:
            continue
        seen.add(key)
        yield Match(
            line=spec.line,
            col=spec.col,
            message=_MESSAGE.format(name=name),
            fix=_FIX,
            data={"variable": name},
        )


client_side_secret = Rule(
    id="client-side-secret",
    title="Credential-ish value read from a client-inlined env var",
    severity=Severity.MEDIUM,
    languages=("javascript",),
    summary=(
        "A NEXT_PUBLIC_/VITE_/REACT_APP_ variable with a credential-ish name "
        "is read into browser code."
    ),
    detectors={"javascript": TextDetector(_detect_javascript)},
    cwe=None,
)
