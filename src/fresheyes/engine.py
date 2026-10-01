"""Scan orchestration: read files, run detectors, apply suppressions."""

from __future__ import annotations

import ast
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .config import Config
from .findings import Finding, Severity
from .rules import ALL_RULES
from .rules.base import Rule, RuleOptions, TextDetector, TreeDetector
from .suppress import parse_suppressions, suppressed
from .walk import KIND_LANGUAGE, MAX_FILE_BYTES, MAX_LINE_CHARS, classify, iter_source_files

__all__ = ["ScanResult", "Scanner", "scan_path", "scan_source"]


@dataclass(slots=True)
class ScanResult:
    """Everything a scan produced."""

    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    parse_errors: list[tuple[str, str]] = field(default_factory=list)
    duration_s: float = 0.0

    @property
    def has_blocking(self) -> bool:
        return bool(self.findings)


class Scanner:
    """Runs the rule set over a set of files."""

    def __init__(self, config: Config | None = None, rules: tuple[Rule, ...] | None = None) -> None:
        self.config = config or Config()
        self.rules = rules if rules is not None else ALL_RULES
        self.enabled_rules = tuple(rule for rule in self.rules if self.config.enabled(rule.id))

    def scan_path(self, target: Path, root: Path | None = None) -> ScanResult:
        """Scan a file or directory tree rooted at *target*."""
        started = time.perf_counter()
        result = ScanResult()
        if root is not None:
            base = root
        elif target.is_file():
            base = target.parent
        else:
            base = target
        for path in iter_source_files(target):
            language = classify(path)
            if language is None:
                continue
            source = self._read(path)
            if source is None:
                result.files_skipped += 1
                continue
            result.files_scanned += 1
            display = _display_path(path, base)
            result.findings.extend(self._scan_text(source, language, display, result))
        result.findings.sort(key=lambda finding: finding.sort_key)
        result.duration_s = time.perf_counter() - started
        return result

    def scan_text(self, source: str, language: str, display_path: str = "<input>") -> ScanResult:
        """Scan in-memory text as if it came from *display_path*."""
        result = ScanResult(files_scanned=1)
        result.findings.extend(self._scan_text(source, language, display_path, result))
        result.findings.sort(key=lambda finding: finding.sort_key)
        return result

    # -- internals -------------------------------------------------------- #

    def _read(self, path: Path) -> str | None:
        """Read *path* as UTF-8 text, or ``None`` when it should be skipped."""
        try:
            size = path.stat().st_size
        except OSError:
            return None
        if size > MAX_FILE_BYTES:
            return None
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return None
        if any(len(line) > MAX_LINE_CHARS for line in text.splitlines()):
            return None
        return text

    def _scan_text(
        self,
        source: str,
        kind: str,
        display_path: str,
        result: ScanResult,
    ) -> Iterator[Finding]:
        language = KIND_LANGUAGE[kind]
        suppressions = parse_suppressions(source)
        tree: ast.AST | None = None
        parsed = True
        for rule in self.enabled_rules:
            detector = rule.detector_for(language)
            if detector is None:
                continue
            if isinstance(detector, TreeDetector):
                if tree is None and parsed:
                    try:
                        tree = ast.parse(source, filename=display_path)
                    except SyntaxError as exc:
                        parsed = False
                        result.parse_errors.append((display_path, exc.msg))
                        tree = None
                if tree is None:
                    continue
                produced = detector.run(tree, source, self._options(rule))
            else:
                assert isinstance(detector, TextDetector)
                produced = detector.run(source, self._options(rule))
            for match in produced:
                if suppressed(suppressions, match.line, rule.id):
                    continue
                yield Finding(
                    path=display_path,
                    line=match.line,
                    col=match.col,
                    rule_id=rule.id,
                    severity=rule.severity,
                    message=match.message or rule.summary,
                    fix=match.fix or "",
                )

    def _options(self, rule: Rule) -> RuleOptions:
        """Per-rule options from configuration, as a plain mapping."""
        return RuleOptions(dict(self.config.options.get(rule.id, {})))


def _display_path(path: Path, base: Path) -> str:
    """Path as shown in findings: relative to *base*, and never a bare dot."""
    try:
        relative = path.relative_to(base)
    except ValueError:
        return path.as_posix()
    text = relative.as_posix()
    return path.name if text == "." else text


def scan_path(target: Path, config: Config | None = None) -> ScanResult:
    """Scan *target* with the default rule set."""
    return Scanner(config).scan_path(target)


def scan_source(source: str, language: str, config: Config | None = None) -> ScanResult:
    """Scan a source string; *language* is ``python``, ``js`` or ``config``."""
    kind = {"python": "python", "js": "js", "javascript": "js", "config": "config"}[language]
    return Scanner(config).scan_text(source, kind)


def blocking(findings: list[Finding], threshold: Severity) -> list[Finding]:
    """Findings at or above *threshold*."""
    return [finding for finding in findings if finding.severity.rank >= threshold.rank]
