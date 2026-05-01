"""Shared test fixtures.

Test data is synthetic. No real customer PII anywhere; fixtures use
generators or obviously-fake values (RFC-2606-reserved domains,
documented AWS example keys, openssl-generated PEMs).
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def policies_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "policies"


@pytest.fixture
def synthetic_pii_prompt() -> str:
    return (
        "Hi team, please debug this for user jane.doe@example.com on host 10.0.13.42. "
        "Connection string: postgres://app:s3cret@db.internal/app_prod . "
        "Auth token attached: eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.aBcDeFgHiJk_LmNoPqR. "
        "Cluster URL https://api.example.com (api ref). "
        "Also AWS key AKIAIOSFODNN7EXAMPLE was leaked yesterday."
    )


@pytest.fixture
def synthetic_clean_prompt() -> str:
    return (
        "Help me write a function that computes the SHA256 of a byte string in Python. "
        "I want it to handle empty inputs and stream-friendly inputs."
    )
