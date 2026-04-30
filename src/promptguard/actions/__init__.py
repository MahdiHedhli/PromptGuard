"""Action engine. Day 1: stub interface; full implementation in Day 2-4.

Per the roadmap (research-notes section 9):
- Day 2 implements BLOCK / MASK primitives and the config schema
- Day 3-4 implement reversible TOKENIZE with streaming
"""

from promptguard.actions.engine import ActionDecision, ActionEngine, ActionOutcome

__all__ = ["ActionDecision", "ActionEngine", "ActionOutcome"]
