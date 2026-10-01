"""Helpers for line-based rules (JavaScript/TypeScript and config files).

No JavaScript parser ships with the standard library, so JS/TS rules match
patterns instead of syntax trees. To keep that honest, every pattern is applied
to a *masked* copy of the file in which comment bodies are blanked out: a
commented-out ``verify: false`` must not be reported, while a string literal
such as ``algorithms: ["none"]`` still must be.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import NamedTuple

__all__ = [
    "LinePattern",
    "PatternSpec",
    "iter_matches",
    "mask_comments",
    "match_patterns",
]

QUOTES = ("'", '"', "`")


class LinePattern(NamedTuple):
    """A compiled pattern plus the wording used when it matches."""

    regex: re.Pattern[str]
    message: str
    fix: str


@dataclass(frozen=True, slots=True)
class PatternSpec:
    """One match inside a file."""

    line: int
    col: int
    end_line: int
    end_col: int
    message: str
    fix: str
    data: dict[str, str]


def mask_comments(source: str) -> str:
    """Return *source* with comment bodies replaced by spaces.

    String and template literals survive intact so patterns can still match
    them. Offsets are unchanged, so a match found in the masked text points at
    the same position in the original file.
    """
    out: list[str] = []
    index = 0
    length = len(source)
    while index < length:
        char = source[index]
        nxt = source[index + 1] if index + 1 < length else ""

        if char in QUOTES:
            index = _copy_string(source, out, index)
            continue
        if char == "/" and nxt == "/":
            index = _blank(source, out, index, source.find("\n", index))
            continue
        if char == "/" and nxt == "*":
            end = source.find("*/", index + 2)
            end = length if end == -1 else end + 2
            index = _blank(source, out, index, end)
            continue
        if char == "#" and not source.startswith("#!", index):
            end = source.find("\n", index)
            index = _blank(source, out, index, length if end == -1 else end)
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _copy_string(source: str, out: list[str], index: int) -> int:
    """Copy a quoted string starting at *index* verbatim; return the end offset."""
    quote = source[index]
    out.append(quote)
    index += 1
    while index < len(source):
        char = source[index]
        if char == "\\":
            out.append(source[index : index + 2])
            index += 2
            continue
        out.append(char)
        index += 1
        if char == quote:
            break
    return index


def _blank(source: str, out: list[str], start: int, end: int) -> int:
    """Blank the span ``[start, end)``, keeping newlines so offsets survive."""
    out.append("".join("\n" if ch == "\n" else " " for ch in source[start:end]))
    return end


def iter_matches(source: str, patterns: Iterable[LinePattern]) -> Iterator[PatternSpec]:
    """Apply *patterns* to the comment-masked *source*.

    Each pattern is searched once over the whole file, so a call split across
    two lines still matches.
    """
    masked = mask_comments(source)
    line_starts = [0, *(m.end() for m in re.finditer("\n", masked))]

    def position(offset: int) -> tuple[int, int]:
        """Convert a character offset into a 1-based (line, column) pair."""
        low, high = 0, len(line_starts) - 1
        while low < high:
            mid = (low + high + 1) // 2
            if line_starts[mid] <= offset:
                low = mid
            else:
                high = mid - 1
        return low + 1, offset - line_starts[low] + 1

    for pattern in patterns:
        for match in pattern.regex.finditer(masked):
            text = match.group(0)
            if not text.strip():
                continue
            line, col = position(match.start())
            end_line, end_col = position(match.end())
            yield PatternSpec(
                line=line,
                col=col,
                end_line=end_line,
                end_col=end_col,
                message=pattern.message.replace("{match}", text.strip()),
                fix=pattern.fix,
                data={key: (value or "") for key, value in match.groupdict().items()},
            )


def match_patterns(source: str, patterns: Iterable[LinePattern]) -> list[PatternSpec]:
    """Convenience wrapper around :func:`iter_matches` returning a list."""
    return list(iter_matches(source, patterns))
