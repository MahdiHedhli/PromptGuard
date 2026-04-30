"""Regex detector coverage.

Each pattern in the baseline set has at least one positive case and one
negative case. When a benchmark fires later, the FP/FN figures will be
generated against AI4Privacy and the GitHub-Issues-Secrets corpus; this
file just guards against regressions.
"""

from __future__ import annotations

import pytest

from promptguard.core.policy import Category
from promptguard.detectors.regex_detector import RegexDetector


@pytest.fixture
def detector() -> RegexDetector:
    return RegexDetector()


# ----------------- POSITIVE CASES -----------------------------------------


@pytest.mark.parametrize(
    ("text", "expected_category"),
    [
        (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpQIBAAKCAQ...\n-----END RSA PRIVATE KEY-----",
            Category.PRIVATE_KEY,
        ),
        (
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA",
            Category.PRIVATE_KEY,
        ),
        ("AKIAIOSFODNN7EXAMPLE", Category.CLOUD_API_KEY),
        ("ASIAY34FZKBOKMUTVV7A", Category.CLOUD_API_KEY),
        ("AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI", Category.CLOUD_API_KEY),
        (
            "DefaultEndpointsProtocol=https;AccountName=stg;AccountKey="
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012345==;"
            "EndpointSuffix=core.windows.net",
            Category.CLOUD_API_KEY,
        ),
        (
            'random text {"type":"service_account","project_id":"foo",'
            '"private_key_id":"abc","private_key":"-----BEGIN..."',
            Category.CLOUD_API_KEY,
        ),
        ("postgres://user:hunter2@db.example.com:5432/app", Category.DATABASE_URL),
        ("postgresql://u:p@h/d", Category.DATABASE_URL),
        ("mysql://root:rootpw@127.0.0.1/wp", Category.DATABASE_URL),
        ("mongodb+srv://app:apppw@cluster0.mongodb.net/prod", Category.DATABASE_URL),
        ("redis://:s3cret@redis.internal:6379/0", Category.DATABASE_URL),
        (
            "eyJhbGciOiJIUzI1NiJ9."
            "eyJzdWIiOiIxMjMiLCJpYXQiOjE2MDAwMDAwMDB9."
            "abcdefghijklmnop",
            Category.JWT,
        ),
        ("Server is at 10.0.0.5", Category.INTERNAL_IP),
        ("internal: 192.168.1.100", Category.INTERNAL_IP),
        ("172.16.5.1 hostmaster", Category.INTERNAL_IP),
        ("contact: alice.smith+filter@example.com please", Category.EMAIL),
        ("the api at api.example.com is up", Category.DOMAIN),
        ("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789", Category.SECRET),
        ("xoxb-1234567890-abcdefghijk", Category.SECRET),
    ],
)
def test_regex_positive(text: str, expected_category: Category, detector: RegexDetector) -> None:
    detections = detector.detect_sync(text)
    cats = {d.category for d in detections}
    assert expected_category in cats, f"expected {expected_category}, got {cats} from {text!r}"


# ----------------- NEGATIVE CASES (no false positives) --------------------


@pytest.mark.parametrize(
    "text",
    [
        "this is plain prose without any sensitive content at all",
        "the function takes a list of integers and returns their sum",
        # Public IPs should NOT be flagged as RFC 1918 internal IPs.
        "google's DNS is at 8.8.8.8",
        # Bare base64 without an aws context should not flag aws-secret.
        "the base64 is QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIz",
    ],
)
def test_regex_negative(text: str, detector: RegexDetector) -> None:
    detections = detector.detect_sync(text)
    blocking_cats = {
        Category.PRIVATE_KEY,
        Category.CLOUD_API_KEY,
        Category.DATABASE_URL,
        Category.JWT,
        Category.SECRET,
        Category.INTERNAL_IP,
    }
    assert not any(d.category in blocking_cats for d in detections), (
        f"unexpected high-severity hit on clean text: "
        f"{[(d.category, d.matched_text) for d in detections]}"
    )


# ----------------- DEDUPE / OVERLAP --------------------------------------


def test_regex_dedupes_overlapping_same_category() -> None:
    """Same-category overlapping spans collapse; different-category spans don't."""
    detector = RegexDetector()
    text = "key: AKIAIOSFODNN7EXAMPLE"
    detections = detector.detect_sync(text)
    aws_hits = [d for d in detections if d.category == Category.CLOUD_API_KEY]
    starts = {d.start for d in aws_hits}
    assert len(starts) == len(aws_hits), "overlapping same-category detections were not deduped"


def test_regex_email_and_domain_coexist() -> None:
    """An email contains a domain; both detections may legitimately fire."""
    detector = RegexDetector()
    text = "ping noreply@example.com tomorrow"
    detections = detector.detect_sync(text)
    cats = {d.category for d in detections}
    assert Category.EMAIL in cats


# ----------------- ASYNC INTERFACE PARITY --------------------------------


async def test_regex_async_matches_sync(synthetic_pii_prompt: str) -> None:
    detector = RegexDetector()
    sync_dets = detector.detect_sync(synthetic_pii_prompt)
    async_dets = await detector.detect(synthetic_pii_prompt)
    assert len(sync_dets) == len(async_dets)
    for a, b in zip(sync_dets, async_dets, strict=True):
        assert (a.category, a.start, a.end) == (b.category, b.start, b.end)
