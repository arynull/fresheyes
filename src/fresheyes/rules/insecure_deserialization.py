"""Rule: insecure-deserialization — loading data that can execute code."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from ..findings import Severity
from .astutils import dotted_name, keyword_value
from .base import LANGUAGES, Match, Rule, RuleOptions, TextDetector, TreeDetector
from .textutils import LinePattern, iter_matches

__all__ = ["insecure_deserialization"]

_RULE_ID = "insecure-deserialization"

#: Reasons reused across several deserializers.
_PICKLE_WHY = "pickle can create arbitrary objects, which means running code"
_SHELVE_WHY = "shelve wraps pickle, so it shares the same risk"
_MARSHAL_WHY = "marshal restores code objects and is unsafe for untrusted data"
_JSONPICKLE_WHY = "jsonpickle can rebuild arbitrary Python objects"

#: ``module.function`` names that deserialize untrusted bytes into live objects.
DESERIALIZERS = {
    "pickle.loads": _PICKLE_WHY,
    "pickle.load": _PICKLE_WHY,
    "cPickle.loads": _PICKLE_WHY,
    "dill.loads": _PICKLE_WHY,
    "dill.load": _PICKLE_WHY,
    "shelve.open": _SHELVE_WHY,
    "shelve.DbfilenameShelf": _SHELVE_WHY,
    "marshal.loads": _MARSHAL_WHY,
    "marshal.load": _MARSHAL_WHY,
    "jsonpickle.decode": _JSONPICKLE_WHY,
    "jsonpickle.unpickler.decode": _JSONPICKLE_WHY,
    "yaml.unsafe_load": "yaml.unsafe_load builds arbitrary Python objects from YAML",
    "yaml.load": "yaml.load without SafeLoader can build arbitrary Python objects",
    "yaml.full_load": "yaml.full_load still resolves some arbitrary Python tags",
}

#: Loader names that make ``yaml.load`` safe.
SAFE_YAML_LOADERS = frozenset(
    {"SafeLoader", "CSafeLoader", "CLoader", "BaseLoader", "SafeConstructor"}
)

MESSAGE = "Untrusted data is deserialized with {call}, and {why}."
FIX = (
    "Use a data-only format for untrusted input: json.loads(payload) for JSON, or "
    "yaml.safe_load(payload) for YAML. If you must accept pickle, authenticate and "
    "encrypt the payload and keep the secret key out of the repository."
)


def _call_name(node: ast.Call) -> str:
    return dotted_name(node.func) or (node.func.id if isinstance(node.func, ast.Name) else "")


def _yaml_loader(node: ast.Call) -> str | None:
    """The loader class named in a ``yaml.load`` call, if any."""
    loader = keyword_value(node, "Loader")
    if isinstance(loader, ast.Name):
        return loader.id
    if isinstance(loader, ast.Attribute):
        return loader.attr
    for arg in node.args[1:]:
        if isinstance(arg, ast.Name):
            return arg.id
        if isinstance(arg, ast.Attribute):
            return arg.attr
    return None


def _detect_python(tree: ast.AST, source: str, options: RuleOptions) -> Iterator[Match]:
    del source, options
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _call_name(node)
        if not name:
            continue
        if name == "yaml.load" and (_yaml_loader(node) or "") in SAFE_YAML_LOADERS:
            continue
        reason = DESERIALIZERS.get(name)
        if reason is None:
            continue
        # ``load(fp)`` over a file object is only as risky as the file itself;
        # bytes/str arguments coming from a caller are the common case, so both
        # are reported — the fix is the same either way.
        yield Match(
            line=node.lineno,
            col=node.col_offset + 1,
            message=MESSAGE.format(call=name, why=reason),
            fix=FIX,
            data={"call": name},
        )


_JS_DESERIALIZERS = [
    (
        re.compile(r"(?i)\bnode-serialize\b"),
        "node-serialize runs any function embedded in the payload",
        "Send plain JSON instead of serialized objects.",
    ),
    (
        re.compile(r"(?i)\byaml\.load\s*\((?![^)]*SafeLoader)"),
        "yaml.load without a safe schema builds arbitrary JavaScript objects",
        "Use yaml.safeLoad(payload) or the JSON parser for untrusted input.",
    ),
    (
        re.compile(r"(?i)\b(?:eval|Function)\s*\(\s*(?:atob|decodeURIComponent|Buffer\.from)\s*\("),
        "decoded text is executed as code",
        "Parse the payload with JSON.parse() instead of executing it.",
    ),
]


def _detect_javascript(source: str, options: RuleOptions) -> Iterator[Match]:
    del options
    patterns = [
        LinePattern(
            regex,
            f"JavaScript deserializes untrusted data unsafely ({why}).",
            fix,
        )
        for regex, why, fix in _JS_DESERIALIZERS
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
            re.compile(r"(?i)^\s*pickle_protocol\s*[:=]"),
            "A pickle protocol setting is present in configuration.",
            "Confirm nothing untrusted is deserialized with pickle; prefer JSON.",
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


insecure_deserialization = Rule(
    id=_RULE_ID,
    title="Unsafe deserialization of untrusted data",
    severity=Severity.HIGH,
    languages=LANGUAGES,
    summary=(
        "Data from outside the program is turned into live objects with a format that can run code."
    ),
    detectors={
        "python": TreeDetector(_detect_python),
        "javascript": TextDetector(_detect_javascript),
        "config": TextDetector(_detect_config),
    },
    cwe="CWE-502",
    references=(
        "https://cwe.mitre.org/data/definitions/502.html",
        "https://owasp.org/www-community/vulnerabilities/Deserialization_of_Untrusted_Data",
    ),
)
