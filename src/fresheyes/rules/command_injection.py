"""Rule: command-injection — shell commands built from untrusted input."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from ..findings import Severity
from .astutils import dotted_name, is_constant, is_dynamic_string, keyword_value
from .base import LANGUAGES, Match, Rule, RuleOptions, TextDetector, TreeDetector
from .textutils import LinePattern, iter_matches

__all__ = ["command_injection"]

_RULE_ID = "command-injection"

#: Functions that always run through a shell.
SHELL_FUNCTIONS = frozenset(
    {"system", "popen", "run", "call", "check_call", "check_output", "spawn"}
)

#: Modules whose ``run``/``call`` family takes ``shell=True`` semantics.
SHELL_MODULES = frozenset({"os", "subprocess", "commands", "popen2", "pty"})

#: Programs whose names mark a single-string command as a shell command.
_COMMAND_PREFIX = r"^\s*(ls|cat|rm|curl|wget|sh|bash|git|npm|docker|echo)\b"

MESSAGE = (
    "A system command is run with {how}, so a value built at runtime can inject extra commands."
)
FIX = (
    "Run the program directly with an argument list and no shell: "
    'subprocess.run(["git", "rev-parse", ref], check=True, shell=False, '
    "capture_output=True, text=True). Validate the value against an allow-list first."
)


def _is_subprocess_module(node: ast.AST) -> bool:
    """Whether the call is made through ``os``/``subprocess``."""
    name = dotted_name(node)
    if not name:
        return False
    root = name.split(".")[0]
    return root in SHELL_MODULES


def _report(node: ast.Call, how: str) -> Match:
    return Match(
        line=node.lineno,
        col=node.col_offset + 1,
        message=MESSAGE.format(how=how),
        fix=FIX,
        data={"how": how},
    )


def _leading_text(node: ast.expr) -> str:
    """The literal text a concatenation or f-string starts with.

    ``"git " + ref`` starts with ``"git "``; an f-string starting with a value
    (``f"{ref} --depth"``) has no static leading text and yields ``""``.
    """
    current: ast.AST = node
    while isinstance(current, (ast.BinOp, ast.JoinedStr)):
        if isinstance(current, ast.JoinedStr):
            if not current.values or not isinstance(current.values[0], ast.Constant):
                return ""
            return str(current.values[0].value)
        if not isinstance(current.op, ast.Add):
            return ""
        current = current.left
    if isinstance(current, ast.Constant) and isinstance(current.value, str):
        return current.value
    return ""


def _starts_with_command(node: ast.expr) -> bool:
    """Whether the command string in *node* begins with a known shell program."""
    return bool(re.match(_COMMAND_PREFIX, _leading_text(node)))


def _detect_python(tree: ast.AST, source: str, options: RuleOptions) -> Iterator[Match]:
    del source, options
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name = dotted_name(node.func) or (
            node.func.id if isinstance(node.func, ast.Name) else ""
        )

        if func_name == "os.system" or func_name.endswith(".system"):
            yield _report(node, "os.system()")
            continue
        if func_name in {"os.popen", "commands.getoutput", "os.spawnl"}:
            yield _report(node, f"{func_name}()")
            continue

        if func_name in {"eval", "exec"}:
            continue

        shell_kw = keyword_value(node, "shell")
        if is_constant(shell_kw, True):
            yield _report(node, f"{func_name}(..., shell=True)")
            continue

        # subprocess.run("git " + ref) — a single string command, no shell.
        if func_name.startswith(("subprocess.", "os.")) and _is_subprocess_module(node.func):
            for arg in node.args:
                if isinstance(arg, (ast.JoinedStr, ast.BinOp)) and is_dynamic_string(arg):
                    if _starts_with_command(arg):
                        yield _report(node, f"{func_name}() with a command string")
                    break


_JS_SHELL = re.compile(
    r"(?is)\b(?:child_process\.)?(?:exec|execSync|spawnSync|execFile|spawn)\s*\(\s*"
    r"(?:`[^`]*\$\{[^}]*\}[^`]*`|['\"][^'\"]*['\"]\s*\+[^,)]*)"
)
_NODE_CHILD = re.compile(
    r"(?is)\bchild_process\.(?:exec|execSync)\s*\(\s*"
    r"(`[^`]*\$\{[^}]*\}[^`]*`|['\"][^'\"]*['\"]\s*\+)"
)


def _detect_javascript(source: str, options: RuleOptions) -> Iterator[Match]:
    del options
    patterns = [
        LinePattern(
            _NODE_CHILD,
            "Node child_process runs a command built from a template string.",
            FIX,
        ),
        LinePattern(
            _JS_SHELL,
            "JavaScript runs a shell command built from dynamic text ({match}).",
            FIX,
        ),
    ]
    seen: set[int] = set()
    for spec in iter_matches(source, patterns):
        if spec.line in seen:
            continue
        seen.add(spec.line)
        yield Match(
            line=spec.line,
            col=spec.col,
            message=spec.message,
            fix=spec.fix,
            data=dict(spec.data),
        )


command_injection = Rule(
    id=_RULE_ID,
    title="Shell command built from dynamic input",
    severity=Severity.HIGH,
    languages=LANGUAGES,
    summary="A system command is executed through a shell with values spliced in at runtime.",
    detectors={
        "python": TreeDetector(_detect_python),
        "javascript": TextDetector(_detect_javascript),
    },
    cwe="CWE-78",
    references=(
        "https://cwe.mitre.org/data/definitions/78.html",
        "https://owasp.org/www-community/attacks/Command_Injection",
    ),
)
