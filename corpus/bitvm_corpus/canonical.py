"""Unambiguous fixture serialization and input validation."""

from __future__ import annotations

import hashlib
import json
from typing import Any


class ValidationError(ValueError):
    """An input violates the Arena contract."""


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode("utf-8")).hexdigest()


def integer(value: Any, name: str, minimum: int = 0, maximum: int = 2**63 - 1) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValidationError(f"{name} must be an integer in [{minimum}, {maximum}]")
    return value


def text(value: Any, name: str, maximum: int = 128) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValidationError(f"{name} must be nonempty text of at most {maximum} characters")
    return value


def keys(value: Any, required: set[str], optional: set[str] = frozenset()) -> dict:
    if not isinstance(value, dict):
        raise ValidationError("expected an object")
    missing, extra = required - value.keys(), value.keys() - required - optional
    if missing or extra:
        raise ValidationError(f"invalid fields; missing={sorted(missing)}, extra={sorted(extra)}")
    return value


def parse_json(content) -> Any:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValidationError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def constant(value):
        raise ValidationError(f"non-finite JSON number: {value}")

    try:
        return json.loads(content, object_pairs_hook=unique, parse_constant=constant)
    except (RecursionError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValidationError(f"invalid JSON: {exc}") from exc


def load_json(path) -> Any:
    with open(path, encoding="utf-8") as handle:
        content = handle.read(16_777_217)
    if len(content) > 16_777_216:
        raise ValidationError("JSON file exceeds 16 MiB")
    return parse_json(content)
