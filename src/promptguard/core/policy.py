"""Policy primitives: categories, actions, rules, detector toggles.

The action semantics are defined in docs/research-notes.md section 5.
The default per-pattern mapping lives in policies/default.yaml.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Action(StrEnum):
    BLOCK = "BLOCK"
    MASK = "MASK"
    TOKENIZE = "TOKENIZE"
    ALLOW = "ALLOW"


class Category(StrEnum):
    PRIVATE_KEY = "private_key"
    CLOUD_API_KEY = "cloud_api_key"
    DATABASE_URL = "database_url"
    JWT = "jwt"
    EMAIL = "email"
    DOMAIN = "domain"
    INTERNAL_IP = "internal_ip"
    CUSTOMER_NAME = "customer_name"
    PRIVATE_NAME = "private_name"
    PRIVATE_PHONE = "private_phone"
    PRIVATE_ADDRESS = "private_address"
    ACCOUNT_NUMBER = "account_number"
    SECRET = "secret"
    OTHER = "other"


class PolicyRule(BaseModel):
    """A single (category -> action) mapping with optional confidence floor.

    `audit_only` per rule (DEC-019): when explicitly set, this rule
    fires audit events only; its action is NOT applied to the request.
    `None` (the default) means inherit the policy-level `audit_only`
    flag, which is `False` unless the operator overrides at the policy
    level. Useful for the workflow "audit-only this one rule for two
    weeks then promote."
    """

    model_config = ConfigDict(extra="forbid")

    category: Category
    action: Action
    min_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    audit_only: bool | None = None


class DetectorToggle(BaseModel):
    """Whether a single detector is enabled in this policy."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True


class DetectorConfig(BaseModel):
    """Per-detector enable flags.

    Defaults match the v1 shipping posture: regex / OPF / Presidio on,
    LLM judge off (research-notes Decision 6).
    """

    model_config = ConfigDict(extra="forbid")

    regex: DetectorToggle = Field(default_factory=DetectorToggle)
    opf: DetectorToggle = Field(default_factory=DetectorToggle)
    presidio: DetectorToggle = Field(default_factory=DetectorToggle)
    llm_judge: DetectorToggle = Field(default_factory=lambda: DetectorToggle(enabled=False))
    # Pre-detection input canonicalization (NFKC, default-ignorable
    # stripping, HTML / URL / base64 decoding). Defends threat-model
    # A8 (encoding-evasion). On by default per DEC-024; the latency
    # cost is sub-millisecond and the security benefit is structural.
    normalization: DetectorToggle = Field(default_factory=DetectorToggle)


class Policy(BaseModel):
    """A full policy: a name, version, detector toggles, and a list of rules."""

    model_config = ConfigDict(extra="forbid")

    name: str
    version: str = "1"
    detectors: DetectorConfig = Field(default_factory=DetectorConfig)
    rules: list[PolicyRule] = Field(default_factory=list)
    audit_only: bool = False

    def action_for(self, category: Category, confidence: float) -> Action:
        for rule in self.rules:
            if rule.category == category and confidence >= rule.min_confidence:
                return rule.action
        return Action.ALLOW

    def is_rule_audit_only(self, category: Category, confidence: float) -> bool:
        """Effective audit_only flag for the rule matching this category.

        Resolution order (DEC-019):
          1. The matching rule's `audit_only`, if explicitly True/False.
          2. The policy-level `audit_only` flag (default False).

        If no rule matches (action ALLOW), the engine drops ALLOW
        detections from the audit path entirely; this method then falls
        back to the policy-level flag, which is academic because nothing
        gets emitted for ALLOWed categories.
        """
        for rule in self.rules:
            if rule.category == category and confidence >= rule.min_confidence:
                if rule.audit_only is not None:
                    return rule.audit_only
                return self.audit_only
        return self.audit_only
