"""LocalYAMLPolicy: reads a policy YAML from disk with line-aware errors.

Schema lives in `promptguard.core.policy.Policy`. See `docs/policy-schema.md`
for the documented surface and example errors.

Line numbers are tracked by a `SafeLoader` subclass that attaches the
source line and column to each scalar / sequence / mapping node. On a
pydantic validation failure we walk the field path produced by pydantic
and look up the matching node to print:

    policy file: policies/default.yaml
      at line 7, column 12 (rules.2.action): expected one of
      ['BLOCK', 'MASK', 'TOKENIZE', 'ALLOW']; got 'REJECT'
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, ClassVar

import yaml
from pydantic import ValidationError

from promptguard.core.policy import Policy
from promptguard.policies.base import PolicyAdapter


class PolicySchemaError(ValueError):
    """Schema validation failed; message includes line, column, field path."""


class _LineTrackingLoader(yaml.SafeLoader):
    """SafeLoader that tags every constructed value with its source position.

    Tags are stored in a parallel dict keyed by the id() of the value object
    that came back from yaml.load. Strings, ints, floats, bools and None are
    not unique objects (Python interns them) so we wrap them in trivial
    helper types that round-trip correctly through the rest of the code.
    """


def _construct_mapping(loader: yaml.SafeLoader, node: yaml.MappingNode) -> dict[str, Any]:
    mapping: dict[str, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        value = loader.construct_object(value_node, deep=True)
        mapping[key] = value
        # Tag this value with its source location for later error reporting.
        _PositionRegistry.record(id(mapping), key, value_node.start_mark)
    _PositionRegistry.record_self(id(mapping), node.start_mark)
    return mapping


def _construct_sequence(loader: yaml.SafeLoader, node: yaml.SequenceNode) -> list[Any]:
    seq: list[Any] = []
    for i, item_node in enumerate(node.value):
        item = loader.construct_object(item_node, deep=True)
        seq.append(item)
        _PositionRegistry.record(id(seq), i, item_node.start_mark)
    _PositionRegistry.record_self(id(seq), node.start_mark)
    return seq


_LineTrackingLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)
_LineTrackingLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_SEQUENCE_TAG, _construct_sequence
)


class _PositionRegistry:
    """Module-scoped scratchpad for parser position info.

    We use a module-scoped dict instead of threading state through the
    loader. yaml.load is synchronous and one-shot; we snapshot per-load.
    """

    _by_container: dict[tuple[int, Any], yaml.error.Mark] = {}
    _self: dict[int, yaml.error.Mark] = {}

    @classmethod
    def reset(cls) -> None:
        cls._by_container = {}
        cls._self = {}

    @classmethod
    def record(cls, container_id: int, key: Any, mark: yaml.error.Mark) -> None:
        cls._by_container[(container_id, key)] = mark

    @classmethod
    def record_self(cls, obj_id: int, mark: yaml.error.Mark) -> None:
        cls._self[obj_id] = mark

    @classmethod
    def lookup(cls, root: Any, path: tuple[Any, ...]) -> yaml.error.Mark | None:
        """Walk the field path, returning the position of the deepest match."""
        if not path:
            return cls._self.get(id(root))
        node: Any = root
        last_mark: yaml.error.Mark | None = cls._self.get(id(root))
        for step in path:
            mark = cls._by_container.get((id(node), step))
            if mark is not None:
                last_mark = mark
            try:
                node = node[step] if isinstance(node, list) else node.get(step)
            except (KeyError, TypeError, IndexError):
                break
            if node is None:
                break
        return last_mark


def _format_pydantic_error(
    raw: dict[str, Any], errors: list[dict[str, Any]], path: Path
) -> str:
    """Render a multi-line PolicySchemaError with line/column for each issue."""
    lines: list[str] = [f"policy file: {path}"]
    for err in errors:
        loc = tuple(err.get("loc", ()))
        path_str = ".".join(str(p) for p in loc) if loc else "<root>"
        mark = _PositionRegistry.lookup(raw, loc)
        if mark is not None:
            location = f"line {mark.line + 1}, column {mark.column + 1}"
        else:
            location = "line ?, column ?"
        msg = err.get("msg", "validation error")
        ctx_value = err.get("input", "<no input>")
        lines.append(f"  at {location} ({path_str}): {msg}; got {ctx_value!r}")
    return "\n".join(lines)


class LocalYAMLPolicy(PolicyAdapter):
    name: ClassVar[str] = "local_yaml"

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)

    @property
    def path(self) -> Path:
        return self._path

    def load(self) -> Policy:
        if not self._path.is_file():
            raise FileNotFoundError(f"policy file not found: {self._path}")

        _PositionRegistry.reset()
        with self._path.open("r", encoding="utf-8") as fh:
            raw: Any = yaml.load(fh, Loader=_LineTrackingLoader)
        if not isinstance(raw, dict):
            raise PolicySchemaError(
                f"policy file: {self._path}\n"
                f"  at line 1, column 1 (<root>): expected a YAML mapping; "
                f"got {type(raw).__name__}"
            )

        try:
            return Policy.model_validate(raw)
        except ValidationError as exc:
            raise PolicySchemaError(
                _format_pydantic_error(raw, exc.errors(include_url=False), self._path)
            ) from exc
