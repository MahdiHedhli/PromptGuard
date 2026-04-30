"""TOKENIZE action: forward path only at v1.

Replaces each detected span with a unique-per-(conversation, original)
token like `[EMAIL_001]`. The mapping (token -> original) is recorded in
a `TokenMap` that lives for the duration of the conversation. The reverse
path that substitutes originals back into streamed responses is Day 3-4
work; for now it is a stubbed identity function.

Token IDs are issued sequentially per category per conversation. This
keeps tokens human-readable in prompts. For threat-model A7 (an LLM
trying to manipulate restoration by emitting a chosen token), the
sequential ID is acceptable because restoration is a pure dict lookup
into a per-conversation map; the LLM cannot guess across conversations.
v1.1 hardening will replace sequential IDs with random ones if a real
attack is demonstrated. See research-notes section 10 question 5.
"""

from __future__ import annotations

from collections import defaultdict
from threading import Lock

from promptguard.actions.base import Action, ActionContext, ActionResult, AuditEntry
from promptguard.core.detection import Detection
from promptguard.core.policy import Category


class TokenMap:
    """In-memory per-conversation map: original <-> token, both directions.

    v1 keeps the map in process memory. Per the threat model (A6) we never
    persist this across process restarts. Day 3-4 will lift this into a
    proper module that handles streaming response rewriting; for v1 the
    forward path is what's wired and the reverse is identity.
    """

    def __init__(self) -> None:
        # conversation_id -> category -> next sequence number
        self._counters: dict[str, dict[Category, int]] = defaultdict(
            lambda: defaultdict(int)
        )
        # conversation_id -> token -> original
        self._token_to_original: dict[str, dict[str, str]] = defaultdict(dict)
        # conversation_id -> (category, original) -> token  (for re-issuing)
        self._original_to_token: dict[str, dict[tuple[Category, str], str]] = (
            defaultdict(dict)
        )
        self._lock = Lock()

    def issue(self, conversation_id: str, category: Category, original: str) -> str:
        """Get or issue a token for `original` in this conversation."""
        with self._lock:
            existing = self._original_to_token[conversation_id].get((category, original))
            if existing is not None:
                return existing
            counter = self._counters[conversation_id]
            counter[category] += 1
            token = f"[{category.value.upper()}_{counter[category]:03d}]"
            self._token_to_original[conversation_id][token] = original
            self._original_to_token[conversation_id][(category, original)] = token
            return token

    def restore(self, conversation_id: str, text: str) -> str:
        """Reverse path. Day 3-4 implements substitution and streaming.

        For Day 2 this is the identity function. The forward path still
        registers tokens so when Day 3-4 lands, every conversation that
        had tokens issued has a working reverse path on the very next call.

        TODO(day-3-4): substitute every issued token in `text` with its
        original value. Handle SSE chunk boundaries per research-notes
        section 6 (streaming TOKENIZE buffering). See also section 10
        question 1 on buffer size.
        """
        return text

    def issued_tokens(self, conversation_id: str) -> dict[str, str]:
        """Snapshot of token -> original for the given conversation."""
        with self._lock:
            return dict(self._token_to_original.get(conversation_id, {}))


class TokenizeAction(Action):
    name: str = "TOKENIZE"

    def __init__(self, token_map: TokenMap) -> None:
        self._token_map = token_map

    def apply(
        self,
        text: str,
        detections: list[Detection],
        context: ActionContext,
    ) -> ActionResult:
        if not detections:
            return ActionResult(text=text)
        ordered = sorted(detections, key=lambda d: (-d.start, -(d.end - d.start)))
        audit: list[AuditEntry] = []
        out = text
        last_start = len(text) + 1
        for d in ordered:
            if d.end > last_start:
                continue
            original = text[d.start : d.end]
            token = self._token_map.issue(
                conversation_id=context.conversation_id,
                category=d.category,
                original=original,
            )
            out = out[: d.start] + token + out[d.end :]
            audit.append(
                AuditEntry(
                    category=d.category.value,
                    detector=d.detector,
                    action=self.name,
                    start=d.start,
                    end=d.end,
                    confidence=d.confidence,
                    replacement=token,
                )
            )
            last_start = d.start
        audit.reverse()
        return ActionResult(text=out, audit=tuple(audit))
