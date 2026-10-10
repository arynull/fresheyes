"""Rule: path-traversal — filesystem paths opened from untrusted input.

Untrusted input used as a file path lets an attacker walk out of the intended
directory (``../../etc/passwd``) and read, overwrite, or delete arbitrary files.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from ..findings import Severity
from .astutils import dotted_name, iter_calls, keyword_value
from .base import LANGUAGES, Match, Rule, RuleOptions, TextDetector, TreeDetector
from .textutils import LinePattern, iter_matches

__all__ = ["path_traversal"]

_RULE_ID = "path-traversal"

MESSAGE = (
    "A filesystem path is opened from a value that is not a fixed literal. An "
    "attacker who controls it can use \"..\" to escape the intended directory and "
    "reach arbitrary files ({where})."
)
FIX = (
    "Resolve the path against a fixed base directory and reject anything that "
    "escapes it: base = Path(BASE_DIR).resolve(); target = (base / user_path).resolve(); "
    "if not target.is_relative_to(base): raise ValueError. Prefer mapping untrusted "
    "input to an allow-list of known filenames."
)

#: Builtins/functions that open a path.
_OPEN_CALLS = frozenset(
    {"open", "io.open", "builtins.open", "os.open", "codecs.open"}
)

#: ``os.path``/``werkzeug`` helpers that collapse a path to a single component.
_SANITIZERS = frozenset({"secure_filename", "basename"})

def _is_literal(node: ast.AST | None) -> bool:
    """Whether *node* is a string constant, i.e. a fixed path."""
    return isinstance(node, ast.Constant) and isinstance(node.value, str)

def _is_static(node: ast.AST | None) -> bool:
    """Whether *node* folds to a literal, so no runtime value reaches the path."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _is_static(node.left) and _is_static(node.right)
    return False

def _is_sanitized(node: ast.expr) -> bool:
    """Whether *node* calls a helper known to strip directory components."""
    if isinstance(node, ast.Call):
        name = dotted_name(node.func)
        if name and name.split(".")[-1] in _SANITIZERS:
            return True
    return False

def _is_untrusted_path(node: ast.expr | None) -> bool:
    """Whether the path expression can carry a value chosen at runtime."""
    if node is None or _is_static(node):
        return False
    if _is_sanitized(node):
        return False
    return isinstance(
        node,
        (ast.Name, ast.Attribute, ast.Subscript, ast.JoinedStr, ast.BinOp, ast.Call),
    )

def _path_argument(node: ast.Call) -> ast.expr | None:
    """The path argument of an ``open``-style call: first positional or ``file=``."""
    if node.args:
        return node.args[0]
    return keyword_value(node, "file")

def _detect_python(tree: ast.AST, source: str, options: RuleOptions) -> Iterator[Match]:
    del source, options
    for node in iter_calls(tree):
        name = dotted_name(node.func)
        if name not in _OPEN_CALLS:
            continue
        path = _path_argument(node)
        if not _is_untrusted_path(path):
            continue
        yield Match(
            line=node.lineno,
            col=node.col_offset + 1,
            message=MESSAGE.format(where=f"{name}()"),
            fix=FIX,
            data={"call": name},
        )

#: Node fs functions that read or open a path.
_JS_FS_FUNCS = (
    r"(?:readFileSync|readFile|createReadStream|openSync|open|"
    r"readdirSync|readdir|accessSync|access|statSync|stat)"
)

#: Names that commonly carry request-controlled input in JavaScript.
_JS_USER = (
    r"(?:req|request|query|params|body|headers|cookies|userInput|user_input|"
    r"userPath|user_path|filePath|file_path|filepath|filename|fileName|"
    r"searchParams|input|upload)"
)

_JS_PATTERNS = (
    LinePattern(
        regex=re.compile(
            rf"\b(?:fs\.)?{_JS_FS_FUNCS}\s*\(\s*`[^`]*\$\{{[^}}]*\b{_JS_USER}\b[^}}]*\}}",
            re.IGNORECASE,
        ),
        message=MESSAGE.format(where="a filesystem call"),
        fix=FIX,
    ),
    LinePattern(
        regex=re.compile(
            rf"\b(?:fs\.)?{_JS_FS_FUNCS}\s*\(\s*(?:[A-Za-z_$][\w$]*\.)*{_JS_USER}\b",
            re.IGNORECASE,
        ),
        message=MESSAGE.format(where="a filesystem call"),
        fix=FIX,
    ),
    LinePattern(
        regex=re.compile(
            rf"\b(?:fs\.)?{_JS_FS_FUNCS}\s*\([^)]*(?:\+[^)]*\b{_JS_USER}\b|\b{_JS_USER}\b[^)]*\+)",
            re.IGNORECASE | re.DOTALL,
        ),
        message=MESSAGE.format(where="a filesystem call"),
        fix=FIX,
    ),
)

def _detect_javascript(source: str, options: RuleOptions) -> Iterator[Match]:
    del options
    seen: set[tuple[int, int]] = set()
    for spec in iter_matches(source, _JS_PATTERNS):
        key = (spec.line, spec.col)
        if key in seen:
            continue
        seen.add(key)
        yield Match(
            line=spec.line,
            col=spec.col,
            message=spec.message,
            fix=spec.fix,
            data=dict(spec.data),
        )

path_traversal = Rule(
    id=_RULE_ID,
    title="Filesystem path built from untrusted input",
    severity=Severity.HIGH,
    languages=LANGUAGES,
    summary="A file is opened using a path assembled from untrusted input, allowing directory traversal.",
    detectors={
        "python": TreeDetector(_detect_python),
        "javascript": TextDetector(_detect_javascript),
    },
    cwe="CWE-22",
    references=(
        "https://cwe.mitre.org/data/definitions/22.html",
        "https://owasp.org/www-community/attacks/Path_Traversal",
    ),
)
