"""Streaming reverse path: text-stream restorer + SSE event rewriter.

Two layers:

  `StreamingRestorer` operates on a plain text stream. It buffers up to
  `MAX_BUFFER` characters (default 256, per research-notes section 10
  question 1). On every `feed(chunk)` it returns the longest stable
  prefix that cannot contain a partial token straddling the boundary.
  `end()` flushes whatever is left.

  `SSEStreamRestorer` operates on a server-sent-event byte stream.
  Every event (`data: {...}\\n\\n`) is parsed; tokens are substituted in
  the JSON payload's text fields; rewritten event is emitted.

Token format: `[CATEGORY_<16+hex>]` (DEC-012). The pattern in
`tokenize._TOKEN_RE` is the source of truth; we re-use it here.

Idempotency note: tokens contain only `[A-Z_a-f0-9\\[\\]]` (no JSON
escape triggers). When we substitute back the original value, we
JSON-escape it before insertion in JSON contexts so nested quotes /
backslashes / newlines do not break the surrounding envelope.
"""

from __future__ import annotations

import json
import re
from typing import Final

from promptguard.actions.tokenize import TokenMap, _TOKEN_RE

DEFAULT_MAX_BUFFER: Final[int] = 256

# A "partial token" is anything that *could grow* into a full token. A
# string that starts with `[`, contains only token-legal chars, and has
# not yet seen the closing `]`. We retain the buffer suffix from the
# last `[` if it matches this pattern.
#
# Token chars are `[A-Z_a-f0-9]`. A complete token must have an
# uppercase category, a single `_` separator, and 16+ hex chars before
# the `]`. While *building*, we cannot tell where the separator falls,
# so we accept any of those chars.
_PARTIAL_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"^\[[A-Z_a-f0-9]*$")


class StreamingRestorer:
    """Text-stream reverse path with partial-token-safe buffering."""

    def __init__(
        self,
        token_map: TokenMap,
        conversation_id: str,
        max_buffer: int = DEFAULT_MAX_BUFFER,
    ) -> None:
        self._tm = token_map
        self._cid = conversation_id
        self._max_buffer = max_buffer
        self._buf: str = ""

    @property
    def buffer_size(self) -> int:
        return len(self._buf)

    def feed(self, chunk: str) -> str:
        """Append `chunk`, return the largest safe-to-emit restored prefix."""
        if not chunk:
            return ""
        self._buf += chunk
        stable, retained = self._split_safe(self._buf)
        self._buf = retained
        if not stable:
            return ""
        return self._tm.restore(self._cid, stable)

    def end(self) -> str:
        """Flush remaining buffer through one final substitution pass."""
        if not self._buf:
            return ""
        out = self._tm.restore(self._cid, self._buf)
        self._buf = ""
        return out

    def _split_safe(self, buf: str) -> tuple[str, str]:
        """Return (flushable_prefix, retained_tail).

        Retain everything from the last `[` if that suffix could still grow
        into a token. Otherwise the whole buffer is flushable. If the
        retained suffix exceeds `max_buffer`, force-flush even if it
        looks like a partial: the buffer should not grow without bound.
        """
        # Where could a partial token start? Only at a `[` that has no
        # closing `]` after it. Scan from the rightmost `[` backward.
        last_bracket = buf.rfind("[")
        if last_bracket < 0:
            return buf, ""
        candidate = buf[last_bracket:]
        # If candidate already contains `]`, it is either a complete
        # token (let restore handle it) or a non-token bracketed string
        # (pass through unchanged). Either way: flush whole buffer.
        if "]" in candidate:
            return buf, ""
        # Could the candidate grow into a token?
        if _PARTIAL_TOKEN_RE.match(candidate) and len(candidate) <= self._max_buffer:
            return buf[:last_bracket], candidate
        # Either too long or contains chars that disqualify it from being
        # a token (e.g. lowercase non-hex, digits 0-9 are hex so OK,
        # whitespace, punctuation). Flush.
        return buf, ""


class SSEStreamRestorer:
    """Server-sent-event reverse path.

    Buffers raw SSE bytes until a complete event boundary (`\\n\\n`),
    then JSON-decodes the `data: ...` payload, substitutes tokens in
    text fields, and re-emits the event. Non-SSE bytes (heartbeats,
    comments, malformed events) pass through unchanged.

    Inside a JSON string value, originals must be JSON-escaped before
    insertion. We use `json.dumps(s)[1:-1]` to get the escaped inner
    content (no surrounding quotes).
    """

    def __init__(
        self,
        token_map: TokenMap,
        conversation_id: str,
    ) -> None:
        self._tm = token_map
        self._cid = conversation_id
        self._byte_buf: bytes = b""

    def feed(self, chunk: bytes) -> bytes:
        """Append `chunk`, emit complete events with substitutions applied."""
        if not chunk:
            return b""
        self._byte_buf += chunk
        out = bytearray()
        while True:
            # SSE event boundary is "\n\n" (LF LF). Some servers use
            # "\r\n\r\n"; we look for either by checking both.
            idx_lf = self._byte_buf.find(b"\n\n")
            idx_crlf = self._byte_buf.find(b"\r\n\r\n")
            if idx_lf < 0 and idx_crlf < 0:
                break
            if idx_lf >= 0 and (idx_crlf < 0 or idx_lf < idx_crlf):
                end = idx_lf + 2
            else:
                end = idx_crlf + 4
            event = self._byte_buf[:end]
            self._byte_buf = self._byte_buf[end:]
            out.extend(self._process_event(event))
        return bytes(out)

    def end(self) -> bytes:
        """Flush remaining buffer (incomplete final event, if any)."""
        if not self._byte_buf:
            return b""
        leftover = self._byte_buf
        self._byte_buf = b""
        return self._process_event(leftover)

    def _process_event(self, event: bytes) -> bytes:
        """Substitute tokens within JSON string contents in the data line.

        Strategy: each line that starts with `data: ` is a JSON payload
        per the SSE spec. We decode the JSON, walk it, find string fields
        commonly carrying text deltas (Anthropic: `delta.text`,
        `content_block.text`; OpenAI: `choices[].delta.content`,
        `choices[].message.content`, `choices[].text`), restore tokens
        in those, and re-encode. Other JSON content is left untouched.
        """
        try:
            text = event.decode("utf-8")
        except UnicodeDecodeError:
            return event
        lines = text.split("\n")
        rewritten_lines: list[str] = []
        for line in lines:
            if line.startswith("data: ") or line.startswith("data:"):
                prefix = "data: " if line.startswith("data: ") else "data:"
                payload = line[len(prefix) :]
                rewritten_lines.append(prefix + self._restore_in_json_payload(payload))
            else:
                rewritten_lines.append(line)
        return "\n".join(rewritten_lines).encode("utf-8")

    def _restore_in_json_payload(self, payload: str) -> str:
        """Decode payload as JSON, restore tokens inside string fields, re-encode.

        If the payload is not valid JSON (e.g. SSE comments, the literal
        `[DONE]` sentinel some servers emit) leave it unchanged.
        """
        stripped = payload.strip()
        if not stripped or stripped.startswith("[") and stripped == "[DONE]":
            return payload
        try:
            obj = json.loads(payload)
        except (json.JSONDecodeError, ValueError):
            return payload
        self._walk_and_restore(obj)
        # Compact JSON re-encoding: matches Anthropic / OpenAI's wire shape.
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)

    def _walk_and_restore(self, obj: object) -> None:
        """In-place walk: substitute tokens in every string value."""
        if isinstance(obj, dict):
            for key, value in list(obj.items()):
                if isinstance(value, str):
                    obj[key] = self._tm.restore(self._cid, value)
                else:
                    self._walk_and_restore(value)
        elif isinstance(obj, list):
            for i, value in enumerate(obj):
                if isinstance(value, str):
                    obj[i] = self._tm.restore(self._cid, value)
                else:
                    self._walk_and_restore(value)


def restore_sse_blob(
    token_map: TokenMap,
    conversation_id: str,
    sse_bytes: bytes,
) -> bytes:
    """Restore tokens in a fully-buffered SSE byte blob.

    Tokens may span multiple `content_block_delta` events because some
    upstreams chunk text deltas at small boundaries (the mock chunks at
    4 chars). Splitting per event and substituting independently does
    not work: a complete token is never present in any one event.

    Strategy:
      1. Parse all events.
      2. Concatenate every `delta.text` (Anthropic) and
         `choices[].delta.content` (OpenAI) field across all events
         into one continuous text.
      3. Run `TokenMap.restore` on the concatenation.
      4. Replace all such delta events with a single
         `content_block_delta` carrying the restored full text.
      5. Pass through every non-text event (message_start, etc.) as-is.

    This compresses many small delta events into one large delta event
    on the wire. Clients that render text incrementally still see the
    correct final text; clients that count delta events get fewer.
    Acceptable trade-off for v1; see DEC-014 for the longer discussion.

    Note: we cannot short-circuit on `_TOKEN_RE.search(raw_bytes)` because
    the token suffix is split across SSE event boundaries by upstream
    chunking. The raw bytes may contain `... "text": "AL_"}}` followed by
    `... "text": "IP_a3f9..."` with the JSON envelope between, so
    `_TOKEN_RE` never finds a complete token in the raw bytes even when
    one exists in the concatenated delta text.
    """
    try:
        sse_text = sse_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return sse_bytes

    # SSE events separated by blank line. Trailing blank line preserved.
    events = sse_text.split("\n\n")
    # The split leaves a trailing empty string if the input ends in \n\n.
    # That's fine; we re-join with \n\n at the end.

    accumulated_text = ""
    # For each event, record whether it's a text-delta event we'll replace,
    # so the rebuild step preserves the order of non-text events.
    is_text_delta: list[bool] = []
    parsed_events: list[tuple[str, dict[str, object] | None]] = []
    for event in events:
        if not event.strip():
            parsed_events.append((event, None))
            is_text_delta.append(False)
            continue
        data_line = None
        for line in event.split("\n"):
            if line.startswith("data: "):
                data_line = line[len("data: ") :]
                break
            if line.startswith("data:"):
                data_line = line[len("data:") :]
                break
        if data_line is None:
            parsed_events.append((event, None))
            is_text_delta.append(False)
            continue
        try:
            payload = json.loads(data_line)
        except (json.JSONDecodeError, ValueError):
            parsed_events.append((event, None))
            is_text_delta.append(False)
            continue
        text = _extract_delta_text(payload)
        if text is None:
            parsed_events.append((event, payload))
            is_text_delta.append(False)
        else:
            accumulated_text += text
            parsed_events.append((event, payload))
            is_text_delta.append(True)

    if not is_text_delta or not any(is_text_delta):
        return sse_bytes

    restored_text = token_map.restore(conversation_id, accumulated_text)

    # Rebuild: keep non-text events as-is; replace the FIRST text-delta event
    # with one carrying the full restored text; drop the rest of the
    # text-delta events. This collapses streaming into one delta event but
    # preserves the surrounding lifecycle events (message_start, _stop).
    replaced_once = False
    rebuilt_events: list[str] = []
    for raw_event, _payload, is_text in zip(
        [pe[0] for pe in parsed_events],
        [pe[1] for pe in parsed_events],
        is_text_delta,
        strict=True,
    ):
        if not is_text:
            rebuilt_events.append(raw_event)
            continue
        if not replaced_once:
            rebuilt_events.append(_build_anthropic_text_delta_event(restored_text))
            replaced_once = True
        # else drop
    return "\n\n".join(rebuilt_events).encode("utf-8")


def _extract_delta_text(payload: object) -> str | None:
    """Return the delta text if this payload is a streaming-text event."""
    if not isinstance(payload, dict):
        return None
    # Anthropic shape: {"type":"content_block_delta", "delta":{"type":"text_delta","text":"..."}}
    delta = payload.get("delta")
    if isinstance(delta, dict):
        text = delta.get("text")
        if isinstance(text, str):
            return text
    # OpenAI shape: {"choices":[{"delta":{"content":"..."}}]}
    choices = payload.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict):
            inner_delta = first.get("delta")
            if isinstance(inner_delta, dict):
                content = inner_delta.get("content")
                if isinstance(content, str):
                    return content
    return None


def _build_anthropic_text_delta_event(text: str) -> str:
    payload = {
        "type": "content_block_delta",
        "index": 0,
        "delta": {"type": "text_delta", "text": text},
    }
    return "event: content_block_delta\ndata: " + json.dumps(
        payload, separators=(",", ":"), ensure_ascii=False
    )


__all__ = [
    "DEFAULT_MAX_BUFFER",
    "SSEStreamRestorer",
    "StreamingRestorer",
    "restore_sse_blob",
]
