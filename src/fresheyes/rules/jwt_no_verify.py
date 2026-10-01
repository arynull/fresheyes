"""Rule: jwt-no-verify — trusting a token nobody signed."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from ..findings import Severity
from .astutils import dotted_name, is_constant, keyword_value
from .base import LANGUAGES, Match, Rule, RuleOptions, TextDetector, TreeDetector
from .textutils import LinePattern, iter_matches

__all__ = ["jwt_no_verify"]

_RULE_ID = "jwt-no-verify"

#: ``options`` keys that switch signature verification off.
VERIFY_OPTIONS = frozenset(
    {
        "verify_signature",
        "verify_exp",
        "verify_aud",
        "verify_nbf",
        "verify_iat",
    }
)

#: Module roots that make a ``decode``/``verify`` call a JWT library call.
JWT_MODULES = frozenset({"jwt", "jose", "jwt_api", "python_jwt", "fastapi_jwt"})

MESSAGE_NO_VERIFY = (
    "This code accepts a JSON Web Token without checking its signature, so anyone "
    "can mint a token with any claims they like."
)
MESSAGE_NONE_ALGO = (
    'This code asks the JWT library to accept the "none" algorithm, which disables '
    "signature checking entirely and lets anyone forge tokens."
)
MESSAGE_NO_KEY = (
    "This code decodes a token without supplying a key or algorithms list, so the "
    "library falls back to defaults that do not verify the signature."
)

FIX = (
    "Verify the token with your server key and an explicit algorithm list: "
    'jwt.decode(token, key, algorithms=["HS256"], options={"require": ["exp", "sub"]}). '
    "Asymmetric tokens need the issuer's public key or JWKS URL, never a shared secret."
)


def _options_dict(node: ast.Call) -> dict[str, ast.expr] | None:
    """The ``options={...}`` keyword of a call, flattened to its entries."""
    options = keyword_value(node, "options")
    if not isinstance(options, ast.Dict):
        return None
    entries: dict[str, ast.expr] = {}
    for key, value in zip(options.keys, options.values, strict=False):
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            entries[key.value] = value
    return entries


def _algorithms(node: ast.Call) -> list[str]:
    """String algorithms listed in the ``algorithms=`` keyword."""
    algorithms = keyword_value(node, "algorithms")
    if not isinstance(algorithms, (ast.List, ast.Tuple)):
        return []
    return [
        element.value
        for element in algorithms.elts
        if isinstance(element, ast.Constant) and isinstance(element.value, str)
    ]


def _detect_python(tree: ast.AST, source: str, options: RuleOptions) -> Iterator[Match]:
    del source, options
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = dotted_name(node.func) or ""
        method = name.rsplit(".", 1)[-1]
        if method not in {"decode", "decode_complete", "decode_token"}:
            continue
        # Only JWT libraries: jwt.decode, jose.jwt.decode, jwt_api.decode.
        root = name.split(".")[0].lower()
        if root not in JWT_MODULES:
            continue

        options_map = _options_dict(node)
        disabled = [
            key
            for key, value in (options_map or {}).items()
            if key in VERIFY_OPTIONS and is_constant(value, False)
        ]
        if disabled:
            keys = ",".join(sorted(disabled))
            yield Match(
                line=node.lineno,
                col=node.col_offset + 1,
                message=MESSAGE_NO_VERIFY,
                fix=FIX,
                data={"reason": "options-disabled", "keys": keys},
            )
            continue

        algorithms = [item.lower() for item in _algorithms(node)]
        if "none" in algorithms:
            yield Match(
                line=node.lineno,
                col=node.col_offset + 1,
                message=MESSAGE_NONE_ALGO,
                fix=FIX,
                data={"reason": "algorithms-none"},
            )
            continue

        # PyJWT >= 2 needs both a key and algorithms; without them it raises,
        # but callers that catch the error fall back to trusting the claims.
        has_key = len(node.args) > 1 or keyword_value(node, "key") is not None
        if not has_key and not algorithms and not (options_map or {}):
            yield Match(
                line=node.lineno,
                col=node.col_offset + 1,
                message=MESSAGE_NO_KEY,
                fix=FIX,
                data={"reason": "missing-key"},
            )


_JS_JWT = re.compile(
    r"(?i)\bjwt\s*\.\s*(?:decode|verify)\s*\("
    r"(?P<args>(?:[^()]|\([^()]*\))*)"
)
_NO_VERIFY_OPT = re.compile(r"(?i)(verify\s*:\s*false|\"none\"|'none'|\bnone\b\s*[,\]])")


def _detect_javascript(source: str, options: RuleOptions) -> Iterator[Match]:
    del options
    patterns = [
        LinePattern(
            _JS_JWT,
            "This JavaScript decodes a JSON Web Token without verifying its signature.",
            FIX,
        ),
    ]
    for spec in iter_matches(source, patterns):
        if not _NO_VERIFY_OPT.search(spec.data.get("args", "")):
            continue
        yield Match(
            line=spec.line,
            col=spec.col,
            message=MESSAGE_NO_VERIFY,
            fix=FIX,
            data=dict(spec.data),
        )


def _detect_config(source: str, options: RuleOptions) -> Iterator[Match]:
    del options
    patterns = [
        LinePattern(
            re.compile(
                r"(?i)\b(?:jwt|JWT)_(?:ALGORITHM|ALG)S?\s*[:=]\s*"
                r"[\"']?(?P<value>none|none\"|none')"
            ),
            "JWT configuration accepts the {value} algorithm, which disables signature checks.",
            FIX,
        ),
    ]
    for spec in iter_matches(source, patterns):
        yield Match(
            line=spec.line,
            col=spec.col,
            message=MESSAGE_NONE_ALGO,
            fix=spec.fix,
            data=dict(spec.data),
        )


jwt_no_verify = Rule(
    id=_RULE_ID,
    title="JWT accepted without signature verification",
    severity=Severity.CRITICAL,
    languages=LANGUAGES,
    summary="A JSON Web Token's claims are trusted without checking who signed it.",
    detectors={
        "python": TreeDetector(_detect_python),
        "javascript": TextDetector(_detect_javascript),
        "config": TextDetector(_detect_config),
    },
    cwe="CWE-347",
    references=(
        "https://cwe.mitre.org/data/definitions/347.html",
        "https://owasp.org/www-community/vulnerabilities/Improper_Verification_of_Cryptographic_Signature",
    ),
)
