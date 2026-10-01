"""Configuration: ``[tool.fresheyes]`` in pyproject.toml or ``.fresheyes.toml``."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import tomllib

from .findings import Severity

try:  # Python < 3.11
    import tomli as _toml_reader
except ModuleNotFoundError:  # pragma: no cover - depends on interpreter version
    _toml_reader = tomllib  # type: ignore[assignment]

__all__ = [
    "CONFIG_FILENAME",
    "Config",
    "ConfigError",
    "PYPROJECT_TABLE",
    "discover",
    "load_file",
]

CONFIG_FILENAME = ".fresheyes.toml"
PYPROJECT_TABLE = "fresheyes"
PYPROJECT_FILENAME = "pyproject.toml"

_SEVERITY_KEYS = ("fail_on_severity", "severity")


class ConfigError(Exception):
    """Raised when a configuration file cannot be used."""


@dataclass(frozen=True, slots=True)
class Config:
    """Effective scanner settings."""

    select: tuple[str, ...] | None = None
    ignore: tuple[str, ...] = ()
    fail_on_severity: Severity = Severity.HIGH
    options: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    source: Path | None = None

    @property
    def source_label(self) -> str:
        return str(self.source) if self.source else "built-in defaults"

    def enabled(self, rule_id: str) -> bool:
        """Whether *rule_id* should run, honouring select/ignore."""
        if rule_id in self.ignore:
            return False
        if self.select is None:
            return True
        return rule_id in self.select

    def option(self, rule_id: str, name: str, default: Any) -> Any:
        """Read a per-rule option, falling back to *default*."""
        return self.options.get(rule_id, {}).get(name, default)


def _as_str_tuple(value: Any, key: str) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, Iterable) and not isinstance(value, (bytes, Mapping)):
        items = list(value)
        if all(isinstance(item, str) for item in items):
            return tuple(items)
    raise ConfigError(f"'{key}' must be a string or a list of strings")


def parse_settings(table: Mapping[str, Any], source: Path | None = None) -> Config:
    """Build a :class:`Config` from a settings mapping."""
    known = {"select", "ignore", *_SEVERITY_KEYS, "rules", "options"}
    unknown = sorted(set(table) - known)
    if unknown:
        raise ConfigError(f"unknown setting(s): {', '.join(unknown)}")

    select_raw = table.get("select")
    select = None if select_raw is None else _as_str_tuple(select_raw, "select")

    ignore_raw = table.get("ignore", [])
    ignore = _as_str_tuple(ignore_raw, "ignore")

    severity_raw = None
    for key in _SEVERITY_KEYS:
        if key in table:
            severity_raw = table[key]
            break
    try:
        fail_on = Severity.parse(severity_raw) if severity_raw is not None else Severity.HIGH
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc

    raw_options = table.get("rules", table.get("options", {}))
    if not isinstance(raw_options, Mapping):
        raise ConfigError("'rules' must be a table of rule id -> options")
    options: dict[str, Mapping[str, Any]] = {}
    for rule_id, values in raw_options.items():
        if not isinstance(values, Mapping):
            raise ConfigError(f"options for rule '{rule_id}' must be a table")
        options[rule_id] = dict(values)

    return Config(
        select=select,
        ignore=ignore,
        fail_on_severity=fail_on,
        options=options,
        source=source,
    )


def load_file(path: Path) -> Config:
    """Load configuration from an explicit ``.fresheyes.toml`` or ``pyproject.toml``."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read config file {path}: {exc.strerror or exc}") from exc
    try:
        data = _toml_reader.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc

    if path.name == PYPROJECT_FILENAME:
        table = data.get("tool", {}).get(PYPROJECT_TABLE)
        if table is None:
            raise ConfigError(f"{path} has no [tool.{PYPROJECT_TABLE}] table")
    else:
        table = data.get("tool", {}).get(PYPROJECT_TABLE, data)
    if not isinstance(table, Mapping):
        raise ConfigError(f"[tool.{PYPROJECT_TABLE}] in {path} must be a table")
    return parse_settings(table, source=path)


def discover(start: Path) -> Config | None:
    """Find configuration by walking up from *start*.

    ``.fresheyes.toml`` wins over ``pyproject.toml`` in the same directory;
    the first directory holding either file decides the result.
    """
    start = start.resolve()
    if start.is_file():
        start = start.parent
    for directory in [start, *start.parents]:
        dedicated = directory / CONFIG_FILENAME
        if dedicated.is_file():
            return load_file(dedicated)
        pyproject = directory / PYPROJECT_FILENAME
        if pyproject.is_file():
            try:
                data = _toml_reader.loads(pyproject.read_bytes().decode("utf-8"))
            except (tomllib.TOMLDecodeError, UnicodeDecodeError, OSError):
                continue
            if isinstance(data.get("tool", {}).get(PYPROJECT_TABLE), Mapping):
                return load_file(pyproject)
    return None
