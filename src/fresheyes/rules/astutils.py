"""Small helpers shared by the AST-based detectors."""

from __future__ import annotations

import ast
from collections.abc import Iterator

__all__ = [
    "ConstantStr",
    "dotted_name",
    "has_star_kwargs",
    "is_constant",
    "is_dynamic_string",
    "iter_calls",
    "keyword",
    "keyword_value",
    "literal",
    "receiver",
    "visit_all",
]

ConstantStr = str


def dotted_name(node: ast.AST) -> str | None:
    """Return ``a.b.c`` for a name/attribute chain, else ``None``.

    ``cursor.execute`` becomes ``"cursor.execute"``; a subscript or call in the
    chain (``get_conn().execute``) returns ``None`` for the whole chain, which
    makes this a deliberately conservative helper.
    """
    parts: list[str] = []
    current: ast.AST = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    return ".".join(reversed(parts))


def receiver(node: ast.Call) -> str | None:
    """For ``x.y(...)`` return ``x``; for a bare ``y(...)`` return ``""``."""
    if isinstance(node.func, ast.Attribute):
        return dotted_name(node.func.value)
    if isinstance(node.func, ast.Name):
        return ""
    return None


def keyword(node: ast.Call, name: str) -> ast.keyword | None:
    """The keyword argument *name* of *node*, if present."""
    for kw in node.keywords:
        if kw.arg == name:
            return kw
    return None


def keyword_value(node: ast.Call, name: str) -> ast.expr | None:
    kw = keyword(node, name)
    return None if kw is None else kw.value


def has_star_kwargs(node: ast.Call) -> bool:
    """Whether the call forwards ``**kwargs``, hiding its real arguments."""
    return any(kw.arg is None for kw in node.keywords)


def literal(node: ast.AST | None) -> ast.Constant | None:
    """*node* as a constant, if it is one."""
    return node if isinstance(node, ast.Constant) else None


def is_constant(node: ast.AST | None, *values: object) -> bool:
    """Whether *node* is a constant equal to any of *values*."""
    const = literal(node)
    if const is None:
        return False
    if not values:
        return True
    return any(const.value == value for value in values)


def _is_static_text(node: ast.AST) -> bool:
    """Whether *node* is built only from literals, so its text never changes."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _is_static_text(node.left) and _is_static_text(node.right)
    return False


def is_dynamic_string(node: ast.AST | None) -> bool:
    """Whether *node* builds a string at runtime.

    True for f-strings, ``%``/``+`` concatenation involving a non-constant, and
    ``str.format``/``.join(...)`` calls. False for plain literals, for constant
    folding such as ``"a" + "b"``, and for a bare name — a variable's value is
    resolved by the caller when that matters.
    """
    if node is None:
        return False
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp):
        if isinstance(node.op, ast.Mod):
            both_constant = isinstance(node.left, ast.Constant) and isinstance(
                node.right, ast.Constant
            )
            return not both_constant
        if isinstance(node.op, ast.Add):
            return not _is_static_text(node)
        return False
    if isinstance(node, ast.Call):
        # ``"literal {x}".format(...)`` has a constant receiver, which
        # :func:`dotted_name` deliberately rejects, so read the attribute too.
        method = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        name = dotted_name(node.func) or ""
        return method in {"format", "join"} or name.endswith(("format", "join"))
    return False


def iter_calls(tree: ast.AST) -> Iterator[ast.Call]:
    """Yield every :class:`ast.Call` in *tree*, outermost first."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            yield node


def visit_all(tree: ast.AST) -> Iterator[ast.AST]:
    """Yield every node in *tree*."""
    return ast.walk(tree)
