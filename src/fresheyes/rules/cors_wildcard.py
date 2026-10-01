"""Rule: cors-wildcard — allowing any site while sending credentials."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from ..findings import Severity
from .astutils import is_constant
from .base import LANGUAGES, Match, Rule, RuleOptions, TextDetector, TreeDetector
from .textutils import LinePattern, iter_matches

__all__ = ["cors_wildcard"]

_RULE_ID = "cors-wildcard"

WILDCARD = "*"

MESSAGE = (
    "This server allows every website ({origin}) while also allowing credentials, so any "
    "page a user visits can call this API as that user and read the response."
)
MESSAGE_SINGLE = (
    "This server reflects the caller's Origin ({origin}) and allows credentials, which "
    "lets any site impersonate a logged-in user."
)

FIX = (
    "Allow only the front-ends you control: "
    'response["Access-Control-Allow-Origin"] = "https://app.example.com", '
    "validate Origin against an allow-list, and add "
    '"Access-Control-Allow-Credentials": "true" only for those trusted origins.'
)


def _response_mapping(node: ast.AST) -> ast.Dict | None:
    """Find the ``response[...] = {...}`` style dictionary for CORS headers."""
    if isinstance(node, ast.Dict):
        return node
    if isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Dict):
        return node.args[0]
    return None


def _dict_entries(mapping: ast.Dict) -> dict[str, ast.expr]:
    entries: dict[str, ast.expr] = {}
    for key, value in zip(mapping.keys, mapping.values, strict=False):
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            entries[key.value.lower()] = value
    return entries


def _origin_is_open(value: ast.expr) -> bool:
    """Whether the Allow-Origin value is ``*`` or reflects the request origin."""
    if is_constant(value, WILDCARD):
        return True
    if isinstance(value, ast.Name):
        return value.id.lower() in {"origin", "request_origin", "req_origin", "http_origin"}
    if isinstance(value, ast.Attribute):
        return value.attr.lower() in {"origin", "headers", "get"}
    if isinstance(value, ast.Subscript):
        return True
    return False


def _detect_python(tree: ast.AST, source: str, options: RuleOptions) -> Iterator[Match]:
    del source, options
    origin_keys = {"access-control-allow-origin", "allow_origin"}
    credential_keys = {"access-control-allow-credentials", "allow_credentials"}
    for node in ast.walk(tree):
        # Only the header mapping matters; the assignment target it lands on
        # only decides whether this counts as a response-header write.
        candidates: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            if any(isinstance(target, ast.Subscript) for target in node.targets):
                candidates.append(node.value)
        elif isinstance(node, ast.Call):
            candidates.extend(
                mapping
                for mapping in (_response_mapping(arg) for arg in node.args)
                if mapping is not None
            )
        for value in candidates:
            entries = _dict_entries(value) if isinstance(value, ast.Dict) else {}
            origin_key = next((key for key in entries if key.lower() in origin_keys), None)
            if origin_key is None:
                continue
            credentials = any(key.lower() in credential_keys for key in entries)
            if not credentials:
                continue
            origin_value = entries[origin_key]
            if not _origin_is_open(origin_value):
                continue
            open_wildcard = is_constant(origin_value, WILDCARD)
            yield Match(
                line=node.lineno,
                col=node.col_offset + 1,
                message=(MESSAGE if open_wildcard else MESSAGE_SINGLE).format(
                    origin="Allow-Origin: *" if open_wildcard else "reflected Origin"
                ),
                fix=FIX,
                data={"origin": WILDCARD if open_wildcard else "reflected"},
            )


_JS_CORS = re.compile(
    r"(?i)[\"']access-control-allow-origin[\"']\s*[:=]\s*"
    r"(?P<origin>['\"]\*['\"]|['\"]['\"]|req\.headers\.[a-z'\"]+|req\.get\([^)]*\))"
)
_JS_CREDENTIALS = re.compile(r"(?i)[\"']access-control-allow-credentials[\"']\s*[:=]\s*['\"]?true")
_JS_CORS_FUNCTION = re.compile(
    r"(?i)cors\s*\(\s*(?P<options>\{[^}]*\})",
    re.DOTALL,
)


def _detect_javascript(source: str, options: RuleOptions) -> Iterator[Match]:
    del options
    credential_pattern = LinePattern(_JS_CREDENTIALS, "", "")
    credentials_lines = {spec.line for spec in iter_matches(source, [credential_pattern])}
    seen: set[int] = set()

    for spec in iter_matches(source, [LinePattern(_JS_CORS, "", "")]):
        line = spec.line
        if line in seen or line not in credentials_lines:
            continue
        seen.add(line)
        yield Match(
            line=line,
            col=spec.col,
            message=MESSAGE.format(origin="Allow-Origin: *"),
            fix=FIX,
            data={},
        )

    for spec in iter_matches(source, [LinePattern(_JS_CORS_FUNCTION, "", "")]):
        line = spec.line
        if line in seen:
            continue
        block = spec.data.get("options", "")
        if "*" not in block or not re.search(r"(?i)credentials\s*:\s*true", block):
            continue
        seen.add(line)
        yield Match(
            line=line,
            col=spec.col,
            message=MESSAGE.format(origin="origin: '*'"),
            fix=FIX,
            data={},
        )


_CONFIG_CORS = re.compile(
    r"(?i)[\"']?(?P<key>access[-_]control[-_]allow[-_]origin|cors[-_]origin|allowed[-_]origins)[\"']?"
    r"\s*[:=]\s*(?P<origin>[\"']?\*[\"']?|\[\s*[\"']\*[\"']\s*\])"
)
_CONFIG_CREDENTIALS = re.compile(
    r"(?i)[\"']?(?:access[-_]control[-_]allow[-_]credentials|allow[-_]credentials|cors[-_]credentials)[\"']?"
    r"\s*[:=]\s*[\"']?true"
)


def _detect_config(source: str, options: RuleOptions) -> Iterator[Match]:
    del options
    pattern = LinePattern(_CONFIG_CREDENTIALS, "", "")
    credential_lines = {spec.line for spec in iter_matches(source, [pattern])}
    patterns = [LinePattern(_CONFIG_CORS, "", "")]
    for spec in iter_matches(source, patterns):
        if spec.line not in credential_lines:
            continue
        yield Match(
            line=spec.line,
            col=spec.col,
            message=MESSAGE.format(origin="Allow-Origin: *"),
            fix=FIX,
            data=dict(spec.data),
        )


cors_wildcard = Rule(
    id=_RULE_ID,
    title="CORS allows any origin together with credentials",
    severity=Severity.MEDIUM,
    languages=LANGUAGES,
    summary="Any website can call this API as a signed-in user and read the response.",
    detectors={
        "python": TreeDetector(_detect_python),
        "javascript": TextDetector(_detect_javascript),
        "config": TextDetector(_detect_config),
    },
    cwe="CWE-942",
    references=(
        "https://cwe.mitre.org/data/definitions/942.html",
        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
    ),
)
