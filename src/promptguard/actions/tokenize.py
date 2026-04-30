"""TOKENIZE action: forward path + reverse path (non-streaming and streaming).

Token format (DEC-012):

    [CATEGORY_<16-hex>]    e.g. [EMAIL_a3f9c1d2e4b56789]

The 16 hex characters come from `secrets.token_hex(8)`, giving 64 bits of
entropy. Sequential IDs were a prompt-injection vector: a malicious LLM
could emit `[EMAIL_001]` to surface another value from the same
conversation map. With unguessable random suffixes the attack requires
~2^63 expected guesses, well outside any prompt-injection budget. See
DEC-012 and threat-model A7.

ConversationTokenMap (DEC-013):

  Per-conversation map evicted by TTL (one hour since last access) and
  max-conversation LRU (100 conversations). Either condition is sufficient
  to evict. Memory budget at worst case is ~25 MB; the bounds exist to
  satisfy the threat-model retention promise (A6), not for memory
  reasons.

Reverse path:

  `restore(conversation_id, text)` finds every token via `_TOKEN_RE` and
  substitutes back from the conversation's own map. Tokens not in the
  map pass through unchanged ("never invent reverse mappings").
"""

from __future__ import annotations

import os
import re
import secrets
import time
from collections import OrderedDict
from threading import Lock
from typing import Final

from promptguard.actions.base import Action, ActionContext, ActionResult, AuditEntry
from promptguard.core.detection import Detection
from promptguard.core.policy import Category

# DEC-012: token format and recogniser pattern. Allows growth past 16 hex
# without code change; we never shrink, so `{16,}` is forward-compatible.
TOKEN_HEX_LEN: Final[int] = 16
_TOKEN_RE: Final[re.Pattern[str]] = re.compile(r"\[[A-Z][A-Z_]*_[a-f0-9]{16,}\]")

# DEC-013: eviction defaults. Operators override via env.
DEFAULT_TTL_SECONDS: Final[int] = int(
    os.environ.get("PROMPTGUARD_TOKEN_MAP_TTL_S", "3600")
)
DEFAULT_MAX_CONVERSATIONS: Final[int] = int(
    os.environ.get("PROMPTGUARD_TOKEN_MAP_MAX_CONVERSATIONS", "100")
)


def is_token_string(s: str) -> bool:
    """True iff `s` is exactly a single PromptGuard token (no surrounding text)."""
    return bool(_TOKEN_RE.fullmatch(s))


def find_tokens(text: str) -> list[re.Match[str]]:
    """Return all token matches in `text`."""
    return list(_TOKEN_RE.finditer(text))


def _new_random_suffix() -> str:
    return secrets.token_hex(TOKEN_HEX_LEN // 2)


class _ConversationState:
    """Per-conversation forward + reverse maps."""

    __slots__ = ("token_to_original", "original_to_token", "last_access_monotonic")

    def __init__(self) -> None:
        self.token_to_original: dict[str, str] = {}
        self.original_to_token: dict[tuple[Category, str], str] = {}
        self.last_access_monotonic: float = time.monotonic()


class TokenMap:
    """Per-conversation token map with TTL + LRU eviction (DEC-013).

    Public API:
      issue(conversation_id, category, original) -> token  (forward)
      restore(conversation_id, text)             -> text   (reverse)
      lookup(conversation_id, token)             -> str | None  (used by streaming)
      issued_tokens(conversation_id)             -> dict   (snapshot, used by tests)

    Eviction runs on every public call. A conversation is evicted if its
    last access is older than `ttl_seconds`, or if the total map size
    exceeds `max_conversations` (oldest by last access dropped first).
    """

    def __init__(
        self,
        max_conversations: int = DEFAULT_MAX_CONVERSATIONS,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        if max_conversations < 1:
            raise ValueError("max_conversations must be >= 1")
        if ttl_seconds < 1:
            raise ValueError("ttl_seconds must be >= 1")
        self._max = max_conversations
        self._ttl = ttl_seconds
        # OrderedDict gives us O(1) move-to-end for LRU touch.
        self._states: OrderedDict[str, _ConversationState] = OrderedDict()
        self._lock = Lock()

    # -- public API --------------------------------------------------

    def issue(self, conversation_id: str, category: Category, original: str) -> str:
        """Get or issue a token for `original` in this conversation.

        Idempotency: a re-issue of the same `(category, original)` in the
        same conversation returns the same token. This is what makes the
        engine idempotent on retag of already-rewritten text.
        """
        with self._lock:
            state = self._touch(conversation_id, create=True)
            existing = state.original_to_token.get((category, original))
            if existing is not None:
                return existing
            # Vanishingly unlikely collision check: token must be unique
            # within this conversation's reverse map. With 64 bits of
            # entropy, retry on collision.
            for _ in range(8):
                token = f"[{category.value.upper()}_{_new_random_suffix()}]"
                if token not in state.token_to_original:
                    state.token_to_original[token] = original
                    state.original_to_token[(category, original)] = token
                    return token
            raise RuntimeError(
                "TokenMap exhausted 8 random-suffix collision retries; "
                "this should be statistically impossible. Check that "
                "secrets.token_hex is not deterministic in this environment."
            )

    def lookup(self, conversation_id: str, token: str) -> str | None:
        """Return the original for a token in this conversation, or None.

        Used by both `restore` and the streaming restorer. Touches LRU.
        """
        with self._lock:
            state = self._touch(conversation_id, create=False)
            if state is None:
                return None
            return state.token_to_original.get(token)

    def restore(self, conversation_id: str, text: str) -> str:
        """Substitute every known token in `text` with its original.

        Tokens not in this conversation's map pass through unchanged.
        Pure string substitution; the LLM never controls a key lookup.
        """
        with self._lock:
            state = self._touch(conversation_id, create=False)
            if state is None or not state.token_to_original:
                return text
            return _TOKEN_RE.sub(
                lambda m: state.token_to_original.get(m.group(0), m.group(0)),
                text,
            )

    def issued_tokens(self, conversation_id: str) -> dict[str, str]:
        """Snapshot copy of token -> original for the given conversation."""
        with self._lock:
            state = self._touch(conversation_id, create=False)
            if state is None:
                return {}
            return dict(state.token_to_original)

    def conversation_count(self) -> int:
        with self._lock:
            self._evict_expired()
            return len(self._states)

    # -- internals ---------------------------------------------------

    def _touch(
        self, conversation_id: str, *, create: bool
    ) -> _ConversationState | None:
        """Return the state, refreshing its LRU position. Caller holds lock."""
        self._evict_expired()
        state = self._states.get(conversation_id)
        if state is None:
            if not create:
                return None
            state = _ConversationState()
            self._states[conversation_id] = state
            self._evict_lru()
        else:
            self._states.move_to_end(conversation_id)
            state.last_access_monotonic = time.monotonic()
        return state

    def _evict_expired(self) -> None:
        now = time.monotonic()
        # Expired entries are the LRU end of the dict. Walk until we find
        # one that's not expired; iterate over a snapshot to avoid mutate-
        # during-iteration.
        to_remove: list[str] = []
        for cid, state in self._states.items():
            if now - state.last_access_monotonic > self._ttl:
                to_remove.append(cid)
            else:
                break  # OrderedDict: earlier entries are older; once we hit
                # a fresh one, the rest are fresh too.
        for cid in to_remove:
            self._states.pop(cid, None)

    def _evict_lru(self) -> None:
        while len(self._states) > self._max:
            self._states.popitem(last=False)


# -- TokenizeAction (forward path) -----------------------------------

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
