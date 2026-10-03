"""Rule: template-injection — a template built from a changing value."""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator

from ..findings import Severity
from .astutils import dotted_name, is_dynamic_string, keyword_value
from .base import Match, Rule, RuleOptions, TextDetector, TreeDetector
from .textutils import LinePattern, iter_matches

__all__ = ["template_injection"]

_RULE_ID = "template-injection"

MESSAGE_FLASK = (
    "This code renders a template built from a value that changes at runtime. "
    "If any part of that template text comes from user input, the input runs "
    "as template code on the server and can read files or other data."
)

MESSAGE_DJANGO = (
    "This code builds a Django template from a value that changes at runtime. "
    "If any part of that template text comes from user input, the input runs "
    "as template code on the server and can read files or other data."
)

MESSAGE_JS = (
    "This code renders a template built from a value that changes at runtime. "
    "If any part of that template text comes from user input, the input runs "
    "as template code on the server."
)

FIX = (
    "Never build a template from user input. Move the markup into a real "
    "template file and call `render_template(...)`, passing user data only as "
    "render variables. If the template itself must vary, pick from an allowlist "
    "of approved fragments — never feed raw request data to "
    "`render_template_string` / `Template()` / `renderString` / `ejs.render`."
)


def _flask_imports(tree: ast.AST) -> tuple[set[str], dict[str, str]]:
    """Collect aliases for the ``flask`` module and its render helper."""
    modules: set[str] = set()
    functions: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "flask":
                    modules.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module == "flask" and node.level == 0:
            for alias in node.names:
                if alias.name == "render_template_string":
                    functions[alias.asname or alias.name] = alias.name
    return modules, functions


def _django_imports(
    tree: ast.AST,
) -> tuple[set[str], set[str], dict[str, str]]:
    """Collect aliases for ``django``, ``django.template`` and ``Template``."""
    django_bases: set[str] = set()
    template_modules: set[str] = set()
    template_names: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "django.template":
                    if alias.asname:
                        template_modules.add(alias.asname)
                    else:
                        django_bases.add("django")
                        template_modules.add("django.template")
                elif alias.name == "django":
                    django_bases.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            if node.module == "django.template":
                for alias in node.names:
                    if alias.name == "Template":
                        template_names[alias.asname or alias.name] = alias.name
            elif node.module == "django":
                for alias in node.names:
                    if alias.name == "template":
                        template_modules.add(alias.asname or alias.name)
    return django_bases, template_modules, template_names


def _is_flask_call(node: ast.Call, modules: set[str], functions: dict[str, str]) -> bool:
    """Whether *node* calls ``flask.render_template_string``."""
    if isinstance(node.func, ast.Name):
        return functions.get(node.func.id) == "render_template_string"
    if isinstance(node.func, ast.Attribute):
        if node.func.attr != "render_template_string":
            return False
        base = dotted_name(node.func.value)
        return base is not None and base in modules
    return False


def _is_django_call(
    node: ast.Call,
    bases: set[str],
    template_modules: set[str],
    template_names: dict[str, str],
) -> bool:
    """Whether *node* constructs ``django.template.Template``."""
    if isinstance(node.func, ast.Name):
        return template_names.get(node.func.id) == "Template"
    if isinstance(node.func, ast.Attribute):
        if node.func.attr != "Template":
            return False
        base = dotted_name(node.func.value)
        if base is None:
            return False
        if base in template_modules:
            return True
        if base == "django.template" and "django" in bases:
            return True
        parts = base.split(".")
        if len(parts) == 2 and parts[1] == "template" and parts[0] in bases:
            return True
        return False
    return False


def _is_dynamic_template_arg(node: ast.AST) -> bool:
    """Whether a template argument is built from a changing value."""
    if isinstance(node, ast.Constant):
        return False
    if isinstance(node, ast.Name):
        return False
    if is_dynamic_string(node):
        return True
    return isinstance(node, (ast.Attribute, ast.Subscript, ast.Call))


def _detect_python(tree: ast.AST, source: str, options: RuleOptions) -> Iterator[Match]:
    del source, options
    flask_modules, flask_functions = _flask_imports(tree)
    django_bases, django_templates, django_names = _django_imports(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        is_flask = _is_flask_call(node, flask_modules, flask_functions)
        is_django = _is_django_call(node, django_bases, django_templates, django_names)
        if not is_flask and not is_django:
            continue
        if node.args:
            template_arg = node.args[0]
        else:
            template_arg = keyword_value(node, "source") or keyword_value(node, "template")
            if template_arg is None:
                continue
        if not _is_dynamic_template_arg(template_arg):
            continue
        message = MESSAGE_FLASK if is_flask else MESSAGE_DJANGO
        yield Match(
            line=node.lineno,
            col=node.col_offset + 1,
            message=message,
            fix=FIX,
        )


_JS_NUNJUCKS = re.compile(r"nunjucks\s*\.\s*renderString\s*\(\s*(?P<arg>[^,)]+)")
_JS_EJS = re.compile(r"\bejs\s*\.\s*render\s*\(\s*(?P<arg>[^,)]+)")


def _is_static_arg(arg: str) -> bool:
    """Whether a JS template argument is a fixed string without pasting."""
    text = arg.strip()
    if not text:
        return True
    return text[0] in ("'", '"') and "+" not in text


def _detect_javascript(source: str, options: RuleOptions) -> Iterator[Match]:
    del options
    patterns = [
        LinePattern(_JS_NUNJUCKS, MESSAGE_JS, FIX),
        LinePattern(_JS_EJS, MESSAGE_JS, FIX),
    ]
    seen: set[int] = set()
    for spec in iter_matches(source, patterns):
        if spec.line in seen:
            continue
        if _is_static_arg(spec.data.get("arg", "")):
            continue
        seen.add(spec.line)
        yield Match(
            line=spec.line,
            col=spec.col,
            message=spec.message,
            fix=spec.fix,
            data=dict(spec.data),
        )


template_injection = Rule(
    id=_RULE_ID,
    title="Server-side template injection from dynamic template source",
    severity=Severity.HIGH,
    languages=("python", "javascript"),
    summary=(
        "User input is interpolated into a template *source* string rendered "
        "by the template engine, so attacker-controlled text executes as template code."
    ),
    detectors={
        "python": TreeDetector(_detect_python),
        "javascript": TextDetector(_detect_javascript),
    },
    cwe="CWE-94",
    references=("https://cwe.mitre.org/data/definitions/94.html",),
)
