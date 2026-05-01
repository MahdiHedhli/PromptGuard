"""Baseline regex pattern set.

Patterns are derived from public, license-compatible sources and adjusted
for our category vocabulary. Attribution is per-pattern below; aggregate
attribution is in /NOTICE.

Sources, all Apache 2.0 / MIT compatible:
  - gitleaks rules (MIT) https://github.com/gitleaks/gitleaks/tree/master/config
  - detect-secrets plugins (Apache 2.0) https://github.com/Yelp/detect-secrets
  - Microsoft Presidio recognizers (MIT) https://github.com/microsoft/presidio

A pattern's `confidence` is conservative; the regex layer is intended to
catch shapes, not adjudicate truth. The OPF and Presidio layers refine
context; the LLM judge (when enabled) catches paraphrased cases.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from promptguard.core.policy import Category


@dataclass(frozen=True, slots=True)
class PatternSpec:
    name: str
    category: Category
    pattern: re.Pattern[str]
    confidence: float
    source: str


def _compile(pattern: str, flags: int = 0) -> re.Pattern[str]:
    return re.compile(pattern, flags)


PATTERNS: tuple[PatternSpec, ...] = (
    # ---- private keys (PEM-format) ---------------------------------------
    PatternSpec(
        name="pem_private_key",
        category=Category.PRIVATE_KEY,
        pattern=_compile(
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED |"
            r"PRIVATE |PRIV )?PRIVATE KEY( BLOCK)?-----"
        ),
        confidence=0.99,
        source="gitleaks:private-key",
    ),
    # ---- AWS credentials --------------------------------------------------
    # AKIA = long-term IAM access key, ASIA = STS temp credentials.
    PatternSpec(
        name="aws_access_key_id",
        category=Category.CLOUD_API_KEY,
        pattern=_compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"),
        confidence=0.95,
        source="gitleaks:aws-access-token",
    ),
    PatternSpec(
        name="aws_secret_access_key",
        category=Category.CLOUD_API_KEY,
        # Heuristic: 40-char base64-ish secrets following an "aws" mention.
        # Lower confidence because shape collides with arbitrary base64.
        pattern=_compile(
            r"(?i)\baws(.{0,20})?(?:secret|key)(.{0,20})?[\"'=:\s]+"
            r"([A-Za-z0-9/+=]{40})\b"
        ),
        confidence=0.7,
        source="gitleaks:aws-secret-access-key",
    ),
    # ---- GCP service account JSON -----------------------------------------
    PatternSpec(
        name="gcp_service_account_json",
        category=Category.CLOUD_API_KEY,
        pattern=_compile(
            r'"type"\s*:\s*"service_account".{0,500}?"private_key"\s*:',
            re.DOTALL,
        ),
        confidence=0.97,
        source="gitleaks:gcp-service-account",
    ),
    PatternSpec(
        name="gcp_api_key",
        category=Category.CLOUD_API_KEY,
        pattern=_compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b"),
        confidence=0.9,
        source="gitleaks:gcp-api-key",
    ),
    # ---- Azure connection string -----------------------------------------
    PatternSpec(
        name="azure_storage_connection_string",
        category=Category.CLOUD_API_KEY,
        pattern=_compile(
            r"DefaultEndpointsProtocol=https?;AccountName=[A-Za-z0-9]+;"
            r"AccountKey=[A-Za-z0-9+/=]{40,};(?:EndpointSuffix=[^;\s]+)?",
        ),
        confidence=0.97,
        source="gitleaks:azure-storage-account-key",
    ),
    PatternSpec(
        name="azure_ad_client_secret",
        category=Category.CLOUD_API_KEY,
        # Azure AD client secret values: 40-char base64 starting with a
        # 3-char prefix. Conservative, matches gitleaks rule shape.
        pattern=_compile(r"\b([A-Za-z0-9_~.\-]{3}[Q~][A-Za-z0-9_~.\-]{31,34})\b"),
        confidence=0.55,
        source="gitleaks:azure-ad-client-secret",
    ),
    # ---- Database URLs ----------------------------------------------------
    # Match scheme://user:password@host[:port]/db; password capture is the
    # part of interest, but we flag the whole URL.
    PatternSpec(
        name="postgres_url",
        category=Category.DATABASE_URL,
        pattern=_compile(
            r"\b(postgres(?:ql)?)://[^\s:@/]+:[^\s:@/]+@[^\s/]+(?:/[^\s]*)?"
        ),
        confidence=0.97,
        source="detect-secrets:keyword + custom",
    ),
    PatternSpec(
        name="mysql_url",
        category=Category.DATABASE_URL,
        pattern=_compile(r"\bmysql://[^\s:@/]+:[^\s:@/]+@[^\s/]+(?:/[^\s]*)?"),
        confidence=0.97,
        source="custom",
    ),
    PatternSpec(
        name="mongodb_url",
        category=Category.DATABASE_URL,
        pattern=_compile(
            r"\bmongodb(?:\+srv)?://[^\s:@/]+:[^\s:@/]+@[^\s/]+(?:/[^\s]*)?"
        ),
        confidence=0.97,
        source="custom",
    ),
    PatternSpec(
        name="redis_url",
        category=Category.DATABASE_URL,
        pattern=_compile(r"\brediss?://(?:[^\s:@/]*:)?[^\s:@/]+@[^\s/]+(?:/[^\s]*)?"),
        confidence=0.95,
        source="custom",
    ),
    # ---- JWT (3-part base64) ---------------------------------------------
    # JWT header always starts with eyJ (base64 of {"). Three dot-separated
    # base64url segments; the last (signature) cannot be empty for HS/RS JWTs.
    PatternSpec(
        name="jwt",
        category=Category.JWT,
        pattern=_compile(
            r"\b(eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"
        ),
        confidence=0.95,
        source="gitleaks:jwt",
    ),
    # ---- RFC 1918 private IPv4 -------------------------------------------
    # 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16. Anchored on word boundaries.
    PatternSpec(
        name="rfc1918_ipv4",
        category=Category.INTERNAL_IP,
        pattern=_compile(
            r"\b(?:"
            r"10\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)"
            r"|172\.(?:1[6-9]|2\d|3[01])\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)"
            r"|192\.168\.(?:25[0-5]|2[0-4]\d|1?\d?\d)\.(?:25[0-5]|2[0-4]\d|1?\d?\d)"
            r")\b"
        ),
        confidence=0.99,
        source="custom (RFC 1918)",
    ),
    # ---- Email -----------------------------------------------------------
    # RFC 5321 is hostile; this is a pragmatic email match.
    PatternSpec(
        name="email",
        category=Category.EMAIL,
        pattern=_compile(
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
        ),
        confidence=0.9,
        source="presidio:EmailRecognizer (shape)",
    ),
    # ---- Domain ----------------------------------------------------------
    # Conservative TLD list for v1; broaden in v1.1 with a public-suffix list.
    PatternSpec(
        name="domain",
        category=Category.DOMAIN,
        pattern=_compile(
            r"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+"
            r"(?:com|net|org|io|ai|co|dev|app|cloud|tech|info|us|uk|de|fr|local|internal|corp)"
            r"\b",
            re.IGNORECASE,
        ),
        confidence=0.7,
        source="custom",
    ),
    # ---- Slack tokens (high-value secret commonly pasted) ----------------
    PatternSpec(
        name="slack_token",
        category=Category.SECRET,
        pattern=_compile(r"\b(xox[baprs]-[A-Za-z0-9\-]{10,})\b"),
        confidence=0.97,
        source="gitleaks:slack-access-token",
    ),
    # ---- GitHub PATs -----------------------------------------------------
    PatternSpec(
        name="github_pat",
        category=Category.SECRET,
        pattern=_compile(r"\b(ghp_[A-Za-z0-9]{36,})\b"),
        confidence=0.99,
        source="gitleaks:github-pat",
    ),
    PatternSpec(
        name="github_fine_grained_pat",
        category=Category.SECRET,
        pattern=_compile(r"\b(github_pat_[A-Za-z0-9_]{82,})\b"),
        confidence=0.99,
        source="gitleaks:github-fine-grained-pat",
    ),
)
