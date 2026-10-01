"""The rule contract: metadata plus the detector interface.

A rule bundles everything a user needs to understand and act on a finding: an
id, a title, a severity, the languages it applies to, a detector per language,
and the plain-language wording used in reports. Detectors come in two flavours:

* :class:`TreeDetector` — receives a parsed ``ast`` tree (Python).
* :class:`TextDetector` — receives the raw file text (JavaScript/TypeScript and
  configuration files, where no parser ships with the standard library).
"""

from __future__ import annotations

import ast
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

from ..findings import Severity

__all__ = [
    "LANGUAGES",
    "Match",
    "Rule",
    "RuleOptions",
    "TextDetector",
    "TreeDetector",
]

#: Languages a rule may declare.
LANGUAGES = ("python", "javascript", "config")

#: Key used by a rule that applies to every language it declares.
ANY_LANGUAGE = "*"


class RuleOptions(dict):
    """Per-rule options, populated from configuration before detection."""


@dataclass(frozen=True, slots=True)
class Match:
    """One suspicious location produced by a detector."""

    line: int
    col: int = 0
    message: str = ""
    fix: str = ""
    #: End of the offending span, when the detector can pin it down.
    end_line: int | None = None
    end_col: int | None = None
    #: Structured context for JSON output and tests.
    data: dict[str, Any] = field(default_factory=dict)


class TreeDetector:
    """Wraps a callable that inspects a parsed syntax tree."""

    __slots__ = ("func",)

    def __init__(self, func: Any) -> None:
        self.func = func

    def run(self, tree: ast.AST, source: str, options: RuleOptions) -> Iterator[Match]:
        yield from self.func(tree, source, options)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"TreeDetector({getattr(self.func, '__qualname__', self.func)})"


class TextDetector:
    """Wraps a callable that inspects raw file text."""

    __slots__ = ("func",)

    def __init__(self, func: Any) -> None:
        self.func = func

    def run(self, source: str, options: RuleOptions) -> Iterator[Match]:
        yield from self.func(source, options)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"TextDetector({getattr(self.func, '__qualname__', self.func)})"


Detector = TreeDetector | TextDetector


@dataclass(frozen=True, slots=True)
class Rule:
    """A check with metadata, a detector, and remediation text."""

    id: str
    title: str
    severity: Severity
    languages: tuple[str, ...]
    summary: str
    detectors: Mapping[str, Detector]
    cwe: str | None = None
    references: tuple[str, ...] = ()
    #: True when the Python detector walks a syntax tree rather than raw text.
    ast_based: bool = True

    def detector_for(self, language: str) -> Detector | None:
        """The detector to run for *language*, or ``None`` if unsupported."""
        detector = self.detectors.get(language) or self.detectors.get(ANY_LANGUAGE)
        if detector is None or language not in self.languages:
            return None
        return detector

    def supports(self, language: str) -> bool:
        """Whether this rule applies to files of the given *language*."""
        return language in self.languages

    @property
    def detector_kind(self) -> str:
        """Human-readable detector description for ``fresheyes rules``."""
        kinds = {
            "ast" if isinstance(detector, TreeDetector) else "pattern"
            for detector in self.detectors.values()
        }
        if not kinds:
            return "pattern"
        return kinds.pop() if len(kinds) == 1 else "ast+pattern"

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "languages": list(self.languages),
            "summary": self.summary,
            "detector": self.detector_kind,
            "cwe": self.cwe,
            "references": list(self.references),
        }
