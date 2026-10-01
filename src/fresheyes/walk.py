"""Decide which files are worth reading."""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path

__all__ = [
    "CONFIG_SUFFIXES",
    "JAVASCRIPT_SUFFIXES",
    "MAX_FILE_BYTES",
    "MAX_LINE_CHARS",
    "PYTHON_SUFFIXES",
    "SKIP_DIRS",
    "SKIP_FILE_NAMES",
    "SKIP_FILE_SUFFIXES",
    "classify",
    "iter_source_files",
]

#: Directories that hold dependencies, build output or bookkeeping — never reviewed.
SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "bower_components",
        "__pycache__",
        "dist",
        "build",
        ".venv",
        "venv",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".eggs",
        "site-packages",
        "vendor",
        "vendors",
        ".next",
        ".nuxt",
        ".cache",
        "htmlcov",
    }
)

#: Minified or bundled files, recognised by name.
SKIP_FILE_SUFFIXES = (".min.js", ".min.jsx", ".min.mjs", ".min.cjs", ".min.ts", ".bundle.js")
SKIP_FILE_NAMES = frozenset({"bundle.js"})

#: Files larger than this are skipped so a stray data file cannot stall the scan.
MAX_FILE_BYTES = 1_000_000

#: A single line longer than this means the file is machine-generated/minified.
MAX_LINE_CHARS = 10_000

PYTHON_SUFFIXES = frozenset({".py", ".pyw", ".pyi"})
JAVASCRIPT_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"})
CONFIG_SUFFIXES = frozenset(
    {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".properties", ".env"}
)

#: Map from the scan "kind" of a file to the language name rules declare.
KIND_LANGUAGE = {"python": "python", "js": "javascript", "config": "config"}


def classify(path: Path) -> str | None:
    """Return the scan kind for *path* (``python``, ``js``, ``config``) or ``None``."""
    name = path.name
    suffix = path.suffix.lower()
    if suffix in PYTHON_SUFFIXES:
        return "python"
    if suffix in JAVASCRIPT_SUFFIXES:
        return "js"
    if name == ".env" or name.startswith(".env."):
        return "config"
    if suffix in CONFIG_SUFFIXES:
        return "config"
    return None


def iter_source_files(target: Path) -> Iterator[Path]:
    """Yield candidate files below *target* in a stable order.

    When *target* is a file it is yielded as-is: pointing the scanner at one
    file is an explicit request, so the directory skip list does not apply.
    """
    if target.is_file():
        yield target
        return
    for dirpath, dirnames, filenames in os.walk(target):
        dirnames[:] = sorted(name for name in dirnames if name not in SKIP_DIRS)
        for name in sorted(filenames):
            if name in SKIP_FILE_NAMES or name.endswith(SKIP_FILE_SUFFIXES):
                continue
            yield Path(dirpath) / name
