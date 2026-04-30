"""JSON-safe extraction and substitution of inspectable strings inside an
LLM request body.

Both Anthropic and OpenAI use a `messages` array of objects whose `content`
is either a string or a list of content blocks. We must inspect and rewrite
the *string values* without disturbing the JSON envelope: tokenizing an
email inside a content block must not break the surrounding object shape.

The strategy is small and explicit:

  1. `extract_inspectable_strings(body)` walks the request body and yields
     `(path, value)` pairs for every string we care about (message contents,
     system prompts, tool descriptions). Path is an opaque list[str | int]
     understood by `set_at_path`.

  2. We concatenate the extracted strings with a delimiter the detectors
     are guaranteed not to match (`\\x00\\x00PG_BOUNDARY\\x00\\x00`), run
     detection and the action engine over the concatenation, then split
     the rewritten result back along the same delimiter and re-insert the
     pieces at their original paths.

The concatenation pass means a span detector cannot accidentally span two
unrelated message contents, and the action engine sees one continuous text
to rewrite.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

# A delimiter that is extremely unlikely to appear in real prompts and
# that no shipped regex matches. NUL bytes plus an ASCII marker.
BOUNDARY = "\x00\x00PG_BOUNDARY\x00\x00"


def extract_inspectable_strings(body: dict[str, Any]) -> list[tuple[list[Any], str]]:
    """Return [(path, string)] for every prompt string we should inspect.

    Inspected fields, by request shape:
      - body["messages"][i]["content"]                            (str)
      - body["messages"][i]["content"][j]["text"]                 (Anthropic content blocks)
      - body["messages"][i]["content"][j]["text"]                 (OpenAI vision-style blocks)
      - body["system"]                                            (Anthropic top-level system)
      - body["system"][j]["text"]                                 (Anthropic structured system)
    Tool definitions are not inspected at v1; tool *outputs* arriving in
    `tool_result` content blocks are.
    """
    out: list[tuple[list[Any], str]] = []

    sys_val = body.get("system")
    if isinstance(sys_val, str):
        out.append((["system"], sys_val))
    elif isinstance(sys_val, list):
        for j, block in enumerate(sys_val):
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                out.append((["system", j, "text"], block["text"]))

    messages = body.get("messages")
    if isinstance(messages, list):
        for i, msg in enumerate(messages):
            if not isinstance(msg, dict):
                continue
            content = msg.get("content")
            if isinstance(content, str):
                out.append((["messages", i, "content"], content))
            elif isinstance(content, list):
                for j, block in enumerate(content):
                    if not isinstance(block, dict):
                        continue
                    # Anthropic + OpenAI: text blocks have type=text + text=...
                    if isinstance(block.get("text"), str):
                        out.append((["messages", i, "content", j, "text"], block["text"]))
                    # Anthropic tool_result blocks may carry a content sub-list.
                    inner = block.get("content")
                    if isinstance(inner, list):
                        for k, sub in enumerate(inner):
                            if isinstance(sub, dict) and isinstance(sub.get("text"), str):
                                out.append(
                                    (
                                        ["messages", i, "content", j, "content", k, "text"],
                                        sub["text"],
                                    )
                                )

    return out


def set_at_path(body: dict[str, Any], path: list[Any], value: str) -> None:
    """In-place update of `body` at `path`."""
    cursor: Any = body
    for step in path[:-1]:
        cursor = cursor[step]
    cursor[path[-1]] = value


def join_for_inspection(strings: list[str]) -> str:
    return BOUNDARY.join(strings)


def split_after_inspection(joined: str, expected_count: int) -> list[str]:
    parts = joined.split(BOUNDARY)
    if len(parts) != expected_count:
        # The action engine should never split or merge our boundary because
        # the boundary contains NULs; raise loudly if it ever does.
        raise ValueError(
            f"PG_BOUNDARY count mismatch after rewrite: "
            f"expected {expected_count}, got {len(parts)}"
        )
    return parts


def iter_strings_in_envelope(body: dict[str, Any]) -> Iterator[str]:
    """Used by tests / the hook for sanity checks.

    Yields every inspected string. Convenience wrapper.
    """
    for _path, s in extract_inspectable_strings(body):
        yield s
