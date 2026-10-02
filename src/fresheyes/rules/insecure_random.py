"""Rule: insecure-random — a security value built from a predictable generator."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from ..findings import Severity
from .base import Match, Rule, RuleOptions, TextDetector, TreeDetector
from .textutils import LinePattern, iter_matches

__all__ = ["insecure_random"]

_RULE_ID = "insecure-random"

#: ``random`` helpers that mint a value. ``random.seed`` is absent on purpose:
#: choosing a seed is a habit worth changing, not a leaked value.
RANDOM_FUNCTIONS = frozenset(
    {
        "choice",
        "choices",
        "randint",
        "randrange",
        "random",
        "uniform",
        "sample",
        "shuffle",
        "getrandbits",
    }
)

#: ``string`` constants that show up as token alphabets.
TOKEN_ALPHABETS = frozenset(
    {
        "ascii_letters",
        "ascii_uppercase",
        "ascii_lowercase",
        "digits",
        "hexdigits",
        "printable",
    }
)

#: A name that marks the value as something an attacker must not predict.
SECURITY_NAME = re.compile(
    r"(?i)(token|secret|password|passwd|pwd|otp|session(_?id)?|api_?key|auth|csrf|nonce|salt|reset)"
)

MESSAGE_SECURITY_NAME = (
    "This code makes {name} with `random`, a generator that is predictable by design: "
    "anyone who sees a few outputs can work out the ones that follow. Values that guard "
    "accounts — tokens, passwords, salts, session ids — must come from the `secrets` module."
)

MESSAGE_ALPHABET = (
    "This code picks characters from `string.{alphabet}` with `random`, whose output an "
    "attacker can predict after seeing a few values, so the result should not protect "
    "anything."
)

FIX = (
    "Use `secrets` instead of `random`: `secrets.token_urlsafe(32)` for tokens, "
    "`secrets.choice(alphabet)` for custom alphabets, `secrets.randbelow(n)` for numbers. "
    "In JavaScript use `crypto.getRandomValues` / `crypto.randomUUID`."
)

MESSAGE_JS_TOKEN = (
    "This code builds a token out of Math.random().toString(36). Math.random() is a "
    "predictable generator, so a token made from it can be guessed by anyone who sees "
    "enough of them."
)

MESSAGE_JS_SECURITY_NAME = (
    "This code assigns Math.random() to a security value. Math.random() is a predictable "
    "generator, so a token, id or key taken from it can be guessed by anyone who sees "
    "enough outputs."
)


def _dotted(node: ast.AST) -> str:
    """``string.ascii_letters`` -> ``string.ascii_letters``; ``t.ok`` -> ``t.ok``."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _random_imports(tree: ast.AST) -> tuple[set[str], dict[str, str]]:
    """Collect names bound to the ``random`` module and to its functions.

    Returns the module aliases (``import random``, ``import random as rnd``) and
    the direct-name imports (``from random import choice``, aliased too) mapped to
    the original member name.
    """
    modules: set[str] = set()
    functions: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "random":
                    modules.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module == "random" and node.level == 0:
            for alias in node.names:
                functions[alias.asname or alias.name] = alias.name
    return modules, functions


def _parent_map(tree: ast.AST) -> dict[ast.AST, ast.AST]:
    """Map every node to the node that contains it."""
    parents: dict[ast.AST, ast.AST] = {}
    stack: list[tuple[ast.AST, ast.AST | None]] = [(tree, None)]
    while stack:
        node, parent = stack.pop()
        for child in ast.iter_child_nodes(node):
            parents[child] = node
            stack.append((child, node))
    return parents


def _random_call(node: ast.Call, modules: set[str], functions: dict[str, str]) -> str | None:
    """The ``random`` member a call invokes, or ``None`` when it is something else."""
    if isinstance(node.func, ast.Attribute):
        if _dotted(node.func.value) in modules and node.func.attr in RANDOM_FUNCTIONS:
            return node.func.attr
        return None
    if isinstance(node.func, ast.Name):
        original = functions.get(node.func.id)
        if original in RANDOM_FUNCTIONS:
            return original
    return None


def _consumes_alphabet(node: ast.Call) -> str | None:
    """The ``string`` alphabet a call draws from, if any."""
    for arg in [*node.args, *(keyword.value for keyword in node.keywords)]:
        if isinstance(arg, ast.Attribute) and _dotted(arg).split(".")[0] == "string":
            if arg.attr in TOKEN_ALPHABETS:
                return arg.attr
    return None


def _target_names(node: ast.AST) -> list[str]:
    """Names an assignment writes to: ``token``, ``self.token``, ``d["api_key"]``."""
    targets: list[ast.AST]
    if isinstance(node, ast.Assign):
        targets = list(node.targets)
    elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
        targets = [node.target]
    else:  # pragma: no cover - guarded by the caller
        return []
    names: list[str] = []
    for target in targets:
        if isinstance(target, ast.Subscript):
            names.append(_dotted(target.value))
            if isinstance(target.slice, ast.Constant) and isinstance(target.slice.value, str):
                names.append(target.slice.value)
            continue
        dotted = _dotted(target)
        if dotted:
            names.append(dotted)
    return names


def _enclosing_names(node: ast.AST, parents: dict[ast.AST, ast.AST]) -> list[str]:
    """Names the call's value flows through: enclosing function, target, keyword."""
    names: list[str] = []
    parent = parents.get(node)
    while parent is not None:
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names.append(parent.name)
        elif isinstance(parent, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            names.extend(_target_names(parent))
        elif isinstance(parent, ast.keyword) and parent.arg:
            names.append(parent.arg)
        parent = parents.get(parent)
    return names


def _detect_python(tree: ast.AST, source: str, options: RuleOptions) -> Iterator[Match]:
    del options, source
    modules, functions = _random_imports(tree)
    parents = _parent_map(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if _random_call(node, modules, functions) is None:
            continue
        line = node.lineno
        col = node.col_offset + 1
        security_name = next(
            (name for name in _enclosing_names(node, parents) if SECURITY_NAME.search(name)),
            None,
        )
        if security_name is not None:
            yield Match(
                line=line,
                col=col,
                message=MESSAGE_SECURITY_NAME.format(name=security_name),
                fix=FIX,
            )
            continue
        alphabet = _consumes_alphabet(node)
        if alphabet:
            yield Match(
                line=line,
                col=col,
                message=MESSAGE_ALPHABET.format(alphabet=alphabet),
                fix=FIX,
            )


_JS_TOKEN_IDIOM = re.compile(r"Math\s*\.\s*random\s*\(\s*\)[\s\S]{0,80}?\.toString\s*\(\s*36\s*\)")
_JS_SECURITY_ASSIGNMENT = re.compile(
    r"(?P<name>[A-Za-z_$][\w$]*)\s*[:=]\s*\(?\s*Math\s*\.\s*random\s*\(\s*\)"
)


def _detect_javascript(source: str, options: RuleOptions) -> Iterator[Match]:
    del options
    patterns = [
        LinePattern(_JS_TOKEN_IDIOM, MESSAGE_JS_TOKEN, FIX),
        LinePattern(_JS_SECURITY_ASSIGNMENT, MESSAGE_JS_SECURITY_NAME, FIX),
    ]
    seen: set[int] = set()
    for spec in iter_matches(source, patterns):
        if spec.line in seen or not _is_security_match(spec.data.get("name", "")):
            continue
        seen.add(spec.line)
        yield Match(
            line=spec.line,
            col=spec.col,
            message=spec.message,
            fix=spec.fix,
            data=dict(spec.data),
        )


def _is_security_match(name: str) -> bool:
    """Whether a JS pattern group names a security value (empty name = token idiom)."""
    return not name or bool(SECURITY_NAME.search(name))


insecure_random = Rule(
    id=_RULE_ID,
    title="Non-cryptographic random for a security value",
    severity=Severity.MEDIUM,
    languages=("python", "javascript"),
    summary=(
        "A token, password, salt, or session id is generated with `random` or `Math.random()`, "
        "which are predictable and not meant for security values."
    ),
    detectors={
        "python": TreeDetector(_detect_python),
        "javascript": TextDetector(_detect_javascript),
    },
    cwe="CWE-338",
    references=("https://cwe.mitre.org/data/definitions/338.html",),
)
