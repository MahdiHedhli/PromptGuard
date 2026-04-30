"""Policy primitives: categories, actions, rules.

The action semantics are defined in docs/research-notes.md section 5.
The default per-pattern mapping lives in policies/default.yaml.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


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
    """A single (category -> action) mapping with optional confidence floor."""

    category: Category
    action: Action
    min_confidence: float = Field(default=0.0, ge=0.0, le=1.0)


class Policy(BaseModel):
    """A full policy: a name, version, and a list of per-category rules."""

    name: str
    version: str = "1"
    rules: list[PolicyRule]
    audit_only: bool = False

    def action_for(self, category: Category, confidence: float) -> Action:
        for rule in self.rules:
            if rule.category == category and confidence >= rule.min_confidence:
                return rule.action
        return Action.ALLOW
