"""Streaming reverse path tests.

Critical invariants:
  * Splitting the input at every byte position yields the same final
    restored output (chunk-boundary independence).
  * SSE event boundaries are preserved (the server's chunking does not
    drop / merge events).
  * Tokens not in this conversation's map pass through unchanged.
  * Cross-conversation isolation holds in the streaming path too.
"""

from __future__ import annotations

import json

import pytest

from promptguard.actions.tokenize import TokenMap
from promptguard.core.policy import Category
from promptguard.proxy.streaming import (
    DEFAULT_MAX_BUFFER,
    SSEStreamRestorer,
    StreamingRestorer,
)


def _tm_with(originals: list[tuple[str, Category, str]]) -> TokenMap:
    tm = TokenMap()
    for cid, category, original in originals:
        tm.issue(cid, category, original)
    return tm


# -- StreamingRestorer text-stream level ---------------------------


def test_streaming_round_trip_no_chunking() -> None:
    tm = TokenMap()
    tok = tm.issue("c", Category.EMAIL, "alice@example.com")
    s = StreamingRestorer(tm, "c")
    out = s.feed(f"send mail to {tok} now")
    out += s.end()
    assert out == "send mail to alice@example.com now"


def test_streaming_unknown_token_passes_through() -> None:
    tm = TokenMap()
    tm.issue("convA", Category.EMAIL, "alice@example.com")
    s = StreamingRestorer(tm, "convB")
    out = s.feed("ping [EMAIL_a3f9c1d2e4b56789] please")
    out += s.end()
    assert out == "ping [EMAIL_a3f9c1d2e4b56789] please"


def test_streaming_split_at_every_byte_position_round_trips() -> None:
    """Streaming must be chunk-boundary independent (validation gate)."""
    tm = TokenMap()
    tok_e = tm.issue("c", Category.EMAIL, "alice@example.com")
    tok_ip = tm.issue("c", Category.INTERNAL_IP, "10.0.0.5")
    full_input = (
        f"Reach out to {tok_e}. "
        f"Server lives at {tok_ip}. "
        f"Repeat: {tok_e} again. End."
    )
    expected = (
        f"Reach out to alice@example.com. "
        f"Server lives at 10.0.0.5. "
        f"Repeat: alice@example.com again. End."
    )
    for split in range(1, len(full_input)):
        s = StreamingRestorer(tm, "c")
        out = s.feed(full_input[:split])
        out += s.feed(full_input[split:])
        out += s.end()
        assert out == expected, f"split at {split}: got {out!r}"


def test_streaming_split_token_byte_by_byte_round_trips() -> None:
    """Stress: feed one char at a time across a payload with multiple tokens."""
    tm = TokenMap()
    tok_a = tm.issue("c", Category.EMAIL, "alice@example.com")
    tok_b = tm.issue("c", Category.EMAIL, "bob@example.com")
    full_input = f"Reply to {tok_a}, cc {tok_b}, then sign off."
    expected = "Reply to alice@example.com, cc bob@example.com, then sign off."
    s = StreamingRestorer(tm, "c")
    out = ""
    for ch in full_input:
        out += s.feed(ch)
    out += s.end()
    assert out == expected


def test_streaming_passes_bracketed_non_token_text_through() -> None:
    """Markdown lists, code, etc. with `[`/`]` must not be retained forever."""
    tm = TokenMap()
    s = StreamingRestorer(tm, "c")
    payload = "Items:\n- [x] one\n- [y] two\nDone."
    out = s.feed(payload) + s.end()
    assert out == payload


def test_streaming_buffer_does_not_grow_without_bound() -> None:
    """A long run of `[A...` (looks-partial) forces flush at MAX_BUFFER."""
    tm = TokenMap()
    s = StreamingRestorer(tm, "c", max_buffer=64)
    looks_partial = "[" + "A" * 200  # exceeds 64
    out = s.feed(looks_partial) + s.end()
    assert out == looks_partial
    assert s.buffer_size == 0


def test_streaming_flush_on_complete_then_more() -> None:
    tm = TokenMap()
    tok = tm.issue("c", Category.EMAIL, "x@example.com")
    s = StreamingRestorer(tm, "c")
    # Feed a complete token followed by more text.
    out = s.feed(f"{tok} hi ")
    # Should be able to flush immediately because nothing is "partial".
    assert out  # at least something flushed
    out += s.feed("there!")
    out += s.end()
    assert out == "x@example.com hi there!"


def test_streaming_default_max_buffer_is_256() -> None:
    assert DEFAULT_MAX_BUFFER == 256


# -- SSEStreamRestorer event level ---------------------------------


def _sse(payload: dict) -> bytes:
    return f"data: {json.dumps(payload)}\n\n".encode()


def test_sse_restores_in_anthropic_text_delta() -> None:
    tm = TokenMap()
    tok = tm.issue("c", Category.EMAIL, "alice@example.com")
    s = SSEStreamRestorer(tm, "c")
    event = _sse(
        {
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": f"reach {tok} please"},
        }
    )
    out = s.feed(event) + s.end()
    payload = json.loads(out.split(b"data: ", 1)[1].rsplit(b"\n\n", 1)[0])
    assert payload["delta"]["text"] == "reach alice@example.com please"


def test_sse_restores_in_openai_choices_delta_content() -> None:
    tm = TokenMap()
    tok = tm.issue("c", Category.INTERNAL_IP, "10.0.0.5")
    s = SSEStreamRestorer(tm, "c")
    event = _sse(
        {
            "id": "chatcmpl-1",
            "choices": [
                {"index": 0, "delta": {"content": f"server: {tok}"}, "finish_reason": None}
            ],
        }
    )
    out = s.feed(event) + s.end()
    payload = json.loads(out.split(b"data: ", 1)[1].rsplit(b"\n\n", 1)[0])
    assert payload["choices"][0]["delta"]["content"] == "server: 10.0.0.5"


def test_sse_passes_done_sentinel_through() -> None:
    tm = TokenMap()
    s = SSEStreamRestorer(tm, "c")
    out = s.feed(b"data: [DONE]\n\n") + s.end()
    assert out == b"data: [DONE]\n\n"


def test_sse_passes_non_data_lines_through() -> None:
    tm = TokenMap()
    s = SSEStreamRestorer(tm, "c")
    raw = (
        b"event: ping\n"
        b": this is a comment\n"
        b"data: {}\n"
        b"\n"
    )
    out = s.feed(raw) + s.end()
    assert b"event: ping" in out
    assert b": this is a comment" in out


def test_sse_chunked_at_arbitrary_byte_positions_preserves_events() -> None:
    """Chunk SSE bytes byte-by-byte; must not lose / merge events."""
    tm = TokenMap()
    tok = tm.issue("c", Category.EMAIL, "alice@example.com")
    events = (
        _sse({"delta": {"text": f"first {tok} chunk."}})
        + _sse({"delta": {"text": "second clean chunk."}})
        + _sse({"delta": {"text": f"third {tok} chunk."}})
    )
    s = SSEStreamRestorer(tm, "c")
    out = b""
    for byte in events:
        out += s.feed(bytes([byte]))
    out += s.end()
    # Three events with restored text.
    assert out.count(b"data: ") == 3
    decoded = out.decode("utf-8")
    assert "first alice@example.com chunk." in decoded
    assert "third alice@example.com chunk." in decoded


def test_sse_handles_crlf_event_boundary() -> None:
    tm = TokenMap()
    tok = tm.issue("c", Category.EMAIL, "alice@example.com")
    s = SSEStreamRestorer(tm, "c")
    event = (
        b'data: {"delta":{"text":"reach '
        + tok.encode("utf-8")
        + b' please"}}\r\n\r\n'
    )
    out = s.feed(event) + s.end()
    decoded = out.decode("utf-8")
    assert "alice@example.com" in decoded


def test_sse_unknown_token_in_stream_passes_through() -> None:
    """Threat A7: an LLM emitting a token from another conversation must
    not be substituted in this conversation's stream."""
    tm = TokenMap()
    tm.issue("convA", Category.EMAIL, "alice@example.com")
    s = SSEStreamRestorer(tm, "convB")
    fake = "[EMAIL_a3f9c1d2e4b56789]"
    event = _sse({"delta": {"text": f"hi {fake} bye"}})
    out = s.feed(event) + s.end()
    decoded = out.decode("utf-8")
    assert fake in decoded
    assert "alice" not in decoded


def test_sse_jsonifies_originals_with_special_chars() -> None:
    """An original containing quote / backslash / newline must remain
    valid JSON after substitution.
    """
    tm = TokenMap()
    tok = tm.issue("c", Category.PRIVATE_NAME, 'O\'Brien "Pat" \\ slash')
    s = SSEStreamRestorer(tm, "c")
    event = _sse({"delta": {"text": f"hello {tok} hello"}})
    out = s.feed(event) + s.end()
    # Re-parsing the data payload must succeed with the special chars.
    raw = out.split(b"data: ", 1)[1].rsplit(b"\n\n", 1)[0]
    decoded_payload = json.loads(raw)
    assert "O'Brien" in decoded_payload["delta"]["text"]
    assert '"Pat"' in decoded_payload["delta"]["text"]


def test_sse_malformed_json_passes_through() -> None:
    tm = TokenMap()
    s = SSEStreamRestorer(tm, "c")
    out = s.feed(b"data: {not json\n\n") + s.end()
    assert b"{not json" in out


def test_restore_sse_blob_preserves_index_field() -> None:
    """When upstream emits text deltas at index != 0 (because earlier
    blocks were thinking / tool_use), the rebuild must preserve the
    original index. claude CLI v2.x produces the "Content block is not
    a text block" error if the rebuilt event's index does not match the
    matching content_block_start. See DEC-020.
    """
    from promptguard.proxy.streaming import restore_sse_blob

    tm = TokenMap()
    tok = tm.issue("c", Category.EMAIL, "alice@example.com")
    sse = (
        # message_start at index=0 covers a thinking block (typical for
        # claude CLI extended-thinking; we just make sure rebuild
        # doesn't touch index).
        b'event: message_start\n'
        b'data: {"type":"message_start","message":{"id":"msg_x"}}\n\n'
        b'event: content_block_start\n'
        b'data: {"type":"content_block_start","index":1,"content_block":{"type":"text","text":""}}\n\n'
        b'event: content_block_delta\n'
        b'data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"Hi "}}\n\n'
        b'event: content_block_delta\n'
        b'data: {"type":"content_block_delta","index":1,"delta":{"type":"text_delta","text":"' + tok.encode() + b'"}}\n\n'
        b'event: content_block_stop\n'
        b'data: {"type":"content_block_stop","index":1}\n\n'
    )
    out = restore_sse_blob(tm, "c", sse)
    decoded = out.decode("utf-8")
    # All content_block_delta events must keep index=1.
    assert '"index":0' not in decoded, f"index 0 leaked into rebuild: {decoded}"
    assert decoded.count('"index":1') >= 3
    # The restored content is present.
    assert "alice@example.com" in decoded


def test_sse_walks_nested_strings() -> None:
    """Must restore tokens inside nested string fields, not just delta.text."""
    tm = TokenMap()
    tok = tm.issue("c", Category.EMAIL, "alice@example.com")
    s = SSEStreamRestorer(tm, "c")
    event = _sse(
        {
            "type": "message_delta",
            "delta": {
                "stop_reason": "end_turn",
                "outputs": [
                    {"type": "text", "text": f"to {tok} from bob"},
                    {"type": "text", "text": "no tokens here"},
                ],
            },
        }
    )
    out = s.feed(event) + s.end()
    decoded = out.decode("utf-8")
    assert "alice@example.com" in decoded
