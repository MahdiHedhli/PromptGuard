"""Action engine: BLOCK, MASK, and (forward-path) TOKENIZE.

Public surface:

    from promptguard.actions import ActionEngine, ActionContext, EngineResult
    from promptguard.actions import TokenMap

Reverse-path TOKENIZE (response rewriting + streaming buffering) lives on
`TokenMap.restore()`; v1 ships it as identity, Day 3-4 fills it in.
"""

from promptguard.actions.base import (
    Action,
    ActionContext,
    ActionResult,
    AuditEntry,
    Violation,
)
from promptguard.actions.block import BlockAction
from promptguard.actions.engine import ActionEngine, EngineResult
from promptguard.actions.mask import MaskAction, mask_tag_for
from promptguard.actions.tokenize import TokenizeAction, TokenMap

__all__ = [
    "Action",
    "ActionContext",
    "ActionEngine",
    "ActionResult",
    "AuditEntry",
    "BlockAction",
    "EngineResult",
    "MaskAction",
    "TokenMap",
    "TokenizeAction",
    "Violation",
    "mask_tag_for",
]
