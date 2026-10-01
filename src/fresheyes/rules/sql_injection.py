"""Rule: sql-injection — SQL built by string interpolation."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from ..findings import Severity
from .astutils import dotted_name, is_dynamic_string
from .base import LANGUAGES, Match, Rule, RuleOptions, TextDetector, TreeDetector
from .textutils import LinePattern, iter_matches

__all__ = ["sql_injection"]

_RULE_ID = "sql-injection"

#: Methods that send a statement to the database.
SQL_METHODS = frozenset(
    {
        "execute",
        "executemany",
        "executescript",
        "exec_driver_sql",
        "execute_sql",
        "raw",
        "rawsql",
    }
)

#: Functions that run raw SQL text.
SQL_FUNCTIONS = frozenset({"raw", "raw_sql", "execute_sql", "text", "query"})

MESSAGE = (
    "SQL is built by pasting values into the query string, so anyone who controls "
    "those values can rewrite the statement ({driver})."
)
FIX = (
    "Pass values as query parameters and keep the SQL in one literal: "
    'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,)) for DB-API, or '
    'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,)) for sqlite3.'
)


#: Keywords that identify a string as a SQL statement.
_SQL_VERB = re.compile(
    r"(?i)\b(select|insert\s+into|update|delete\s+from|drop\s+table|union\s+select)\b"
)


def _is_sql_statement(text: str) -> bool:
    """Whether *text* looks like a SQL statement."""
    return bool(_SQL_VERB.search(text))


def _dynamic_arguments(node: ast.Call) -> list[ast.expr]:
    """Arguments of *node* whose text is assembled at runtime."""
    args = list(node.args)
    for kw in node.keywords:
        if kw.arg in {"sql", "query", "statement", "query_string"}:
            args.append(kw.value)
    return [arg for arg in args if is_dynamic_string(arg)]


def _statement_text(node: ast.Call) -> str:
    """Best-effort static text of the first argument, for reporting."""
    if node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
        return node.args[0].value
    try:
        return ast.unparse(node.args[0]) if node.args else ""
    except Exception:  # pragma: no cover - unparse is total in practice
        return ""


#: Database libraries recognised in a call chain, for the message wording.
_SQL_LIBRARIES = (
    "sqlite3",
    "psycopg",
    "pymysql",
    "sqlalchemy",
    "psycopg2",
    "asyncpg",
    "django",
    "mysql",
)


def _sql_driver(func: ast.expr) -> str:
    """A short label for the DB library being used, for the message."""
    name = dotted_name(func) or ""
    lowered = name.lower()
    for library in _SQL_LIBRARIES:
        if library in lowered:
            return library
    return name.split(".")[0] or "database driver"


def _detect_python(tree: ast.AST, source: str, options: RuleOptions) -> Iterator[Match]:
    del source, options
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Attribute):
            method = node.func.attr
        elif isinstance(node.func, ast.Name):
            method = node.func.id
        else:
            continue
        if method not in SQL_METHODS and method not in SQL_FUNCTIONS:
            continue
        dynamic = _dynamic_arguments(node)
        if not dynamic:
            continue
        text = _statement_text(node)
        if text and not _is_sql_statement(text):
            continue
        yield Match(
            line=node.lineno,
            col=node.col_offset + 1,
            message=MESSAGE.format(driver=_sql_driver(node.func)),
            fix=FIX,
            data={"call": method, "driver": _sql_driver(node.func)},
        )


_JS_TEMPLATE_SQL = re.compile(
    r"(?is)\b(?:query|execute|raw|prepare)\s*\(\s*[`\"']\s*(?:select|insert\s+into|update|delete\s+from)"
    r"[^`\"']*(?:\$\{|['\"]\s*\+)"
)


def _detect_javascript(source: str, options: RuleOptions) -> Iterator[Match]:
    del options
    patterns = [
        LinePattern(
            _JS_TEMPLATE_SQL,
            "JavaScript builds a SQL string with interpolation or concatenation ({match}).",
            FIX,
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


sql_injection = Rule(
    id=_RULE_ID,
    title="SQL query built with string interpolation",
    severity=Severity.HIGH,
    languages=LANGUAGES,
    summary="A SQL statement is assembled from variables instead of bound parameters.",
    detectors={
        "python": TreeDetector(_detect_python),
        "javascript": TextDetector(_detect_javascript),
    },
    cwe="CWE-89",
    references=(
        "https://cwe.mitre.org/data/definitions/89.html",
        "https://owasp.org/www-community/attacks/SQL_Injection",
    ),
)
