"""Audit shipped sample policies against the locked default mapping.

Research-notes section 5 lists the locked default per-category actions.
This test guards against drift in those values without requiring the
operator to manually compare the YAML against the markdown.

Each sample policy is also exercised end-to-end: load via
`LocalYAMLPolicy`, then assert specific (category, action) pairs that
are characteristic of that policy's intent (BLOCK on credentials in
every shipped policy, MASK vs TOKENIZE differentiation between policies).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from promptguard.core.policy import Action, Category
from promptguard.policies.local_yaml import LocalYAMLPolicy

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICIES_DIR = REPO_ROOT / "policies"


# Locked default mapping from research-notes section 5. Categories not
# listed here are operator-extension and audited per-policy below.
LOCKED_DEFAULT: dict[Category, Action] = {
    Category.PRIVATE_KEY: Action.BLOCK,
    Category.CLOUD_API_KEY: Action.BLOCK,
    Category.DATABASE_URL: Action.BLOCK,
    Category.JWT: Action.BLOCK,
    Category.EMAIL: Action.MASK,
    Category.DOMAIN: Action.TOKENIZE,
    Category.INTERNAL_IP: Action.TOKENIZE,
    Category.CUSTOMER_NAME: Action.TOKENIZE,
}


def test_default_policy_matches_research_notes_section_5() -> None:
    policy = LocalYAMLPolicy(POLICIES_DIR / "default.yaml").load()
    for category, expected in LOCKED_DEFAULT.items():
        actual = policy.action_for(category, 1.0)
        assert actual == expected, (
            f"default.yaml drift on {category.value}: "
            f"expected {expected}, got {actual} (research-notes section 5)"
        )


@pytest.mark.parametrize(
    "policy_name",
    ["default", "nda-strict", "healthcare-leaning", "regex-only", "pentest-engagement"],
)
def test_every_policy_blocks_credentials(policy_name: str) -> None:
    """Credentials must BLOCK in every shipped policy regardless of intent."""
    policy = LocalYAMLPolicy(POLICIES_DIR / f"{policy_name}.yaml").load()
    for category in (
        Category.PRIVATE_KEY,
        Category.CLOUD_API_KEY,
        Category.DATABASE_URL,
        Category.JWT,
        Category.SECRET,
    ):
        assert policy.action_for(category, 1.0) == Action.BLOCK, (
            f"{policy_name}.yaml does not BLOCK {category.value}; "
            "credential categories must always BLOCK."
        )


def test_nda_strict_escalates_email_and_customer_name_to_block() -> None:
    policy = LocalYAMLPolicy(POLICIES_DIR / "nda-strict.yaml").load()
    assert policy.action_for(Category.EMAIL, 1.0) == Action.BLOCK
    assert policy.action_for(Category.CUSTOMER_NAME, 1.0) == Action.BLOCK


def test_healthcare_leaning_masks_personal_identifiers() -> None:
    """PHI-adjacent: no TOKENIZE on personal data (no ledger)."""
    policy = LocalYAMLPolicy(POLICIES_DIR / "healthcare-leaning.yaml").load()
    for category in (
        Category.PRIVATE_NAME,
        Category.PRIVATE_PHONE,
        Category.PRIVATE_ADDRESS,
        Category.EMAIL,
        Category.DOMAIN,
        Category.INTERNAL_IP,
        Category.CUSTOMER_NAME,
    ):
        assert policy.action_for(category, 1.0) == Action.MASK, (
            f"healthcare-leaning must MASK {category.value} (no ledger), "
            f"got {policy.action_for(category, 1.0)}"
        )


def test_pentest_engagement_blocks_customer_infrastructure() -> None:
    """Pentest engagements contractually forbid retention of customer infra."""
    policy = LocalYAMLPolicy(POLICIES_DIR / "pentest-engagement.yaml").load()
    for category in (
        Category.DOMAIN,
        Category.INTERNAL_IP,
        Category.CUSTOMER_NAME,
        Category.ACCOUNT_NUMBER,
    ):
        assert policy.action_for(category, 1.0) == Action.BLOCK, (
            f"pentest-engagement must BLOCK {category.value} "
            f"(customer infrastructure is identifying), got "
            f"{policy.action_for(category, 1.0)}"
        )


def test_regex_only_disables_opf_and_presidio() -> None:
    policy = LocalYAMLPolicy(POLICIES_DIR / "regex-only.yaml").load()
    assert policy.detectors.regex.enabled is True
    assert policy.detectors.opf.enabled is False
    assert policy.detectors.presidio.enabled is False


