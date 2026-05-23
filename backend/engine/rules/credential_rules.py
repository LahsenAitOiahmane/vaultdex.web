"""
SecureStorageInspector — Credential Detection Rules

Detects passwords, API keys, auth tokens, bearer tokens, client secrets,
and other authentication credentials stored in plaintext.

These are the highest-severity rules: plaintext credentials in local
storage are an immediate security risk on any rooted device or backup
extraction.
"""

from __future__ import annotations

from typing import List

from backend.engine.models import Severity, StorageArea
from backend.engine.rules_engine import SecurityRule


_ALL_AREAS = list(StorageArea)


def get_rules() -> List[SecurityRule]:
    """Return all credential-related security rules."""
    return [
        # ── Passwords ────────────────────────────────────────────────
        SecurityRule(
            id="CRED-001",
            name="Plaintext Password",
            description=(
                "A value associated with a password-related key was found "
                "stored in plaintext. Passwords must never be stored locally "
                "in cleartext — use Android Keystore or server-side hashing."
            ),
            severity=Severity.CRITICAL,
            category="credentials",
            key_patterns=[
                r"password",
                r"passwd",
                r"pass_word",
                r"user_pass",
                r"login_pass",
                r"pwd",
            ],
            value_patterns=[],
            applies_to=_ALL_AREAS,
            match_target="key",
            recommendation=(
                "Remove plaintext password storage. Use Android Keystore for "
                "local secrets, or store only a server-issued session token."
            ),
            min_value_length=1,
        ),

        # ── API Keys ─────────────────────────────────────────────────
        SecurityRule(
            id="CRED-002",
            name="Plaintext API Key",
            description=(
                "An API key or secret key was found in plaintext local storage. "
                "API keys grant access to external services and must not be "
                "embedded in client-side storage."
            ),
            severity=Severity.CRITICAL,
            category="credentials",
            key_patterns=[
                r"api[_\-]?key",
                r"api[_\-]?secret",
                r"secret[_\-]?key",
                r"app[_\-]?key",
                r"app[_\-]?secret",
                r"client[_\-]?secret",
                r"consumer[_\-]?key",
                r"consumer[_\-]?secret",
            ],
            value_patterns=[],
            applies_to=_ALL_AREAS,
            match_target="key",
            recommendation=(
                "Move API keys to a backend proxy (BFF pattern). Never store "
                "API secrets on the client. Use OAuth tokens with short expiry."
            ),
            min_value_length=8,
        ),

        # ── Auth / Bearer Tokens ─────────────────────────────────────
        SecurityRule(
            id="CRED-003",
            name="Plaintext Auth Token",
            description=(
                "An authentication or bearer token was found stored in plaintext. "
                "Tokens are equivalent to session credentials and must be "
                "protected with EncryptedSharedPreferences or Android Keystore."
            ),
            severity=Severity.CRITICAL,
            category="credentials",
            key_patterns=[
                r"auth[_\-]?token",
                r"access[_\-]?token",
                r"bearer[_\-]?token",
                r"refresh[_\-]?token",
                r"id[_\-]?token",
                r"jwt[_\-]?token",
                r"token",
            ],
            value_patterns=[],
            applies_to=_ALL_AREAS,
            match_target="key",
            recommendation=(
                "Store tokens using EncryptedSharedPreferences or the Android "
                "Keystore system. Set short expiry times and implement token "
                "refresh flows server-side."
            ),
            min_value_length=10,
        ),

        # ── JWT Detection by Value ───────────────────────────────────
        SecurityRule(
            id="CRED-004",
            name="JWT Token in Storage",
            description=(
                "A JSON Web Token (JWT) was detected in local storage. JWTs "
                "contain encoded claims and may include sensitive user data. "
                "They must be stored securely, not in plaintext files."
            ),
            severity=Severity.HIGH,
            category="credentials",
            key_patterns=[],
            value_patterns=[
                # JWT: three base64url segments separated by dots
                r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+",
            ],
            applies_to=_ALL_AREAS,
            match_target="value",
            recommendation=(
                "Store JWTs in EncryptedSharedPreferences. Avoid long-lived "
                "tokens — use short-expiry access tokens with refresh rotation."
            ),
            min_value_length=20,
        ),

        # ── OAuth Credentials ────────────────────────────────────────
        SecurityRule(
            id="CRED-005",
            name="OAuth Client Credentials",
            description=(
                "OAuth client credentials (client_id or client_secret) were "
                "found in local storage. Client secrets must never be embedded "
                "in mobile applications."
            ),
            severity=Severity.HIGH,
            category="credentials",
            key_patterns=[
                r"client[_\-]?id",
                r"client[_\-]?secret",
                r"oauth[_\-]?token",
                r"oauth[_\-]?secret",
            ],
            value_patterns=[],
            applies_to=_ALL_AREAS,
            match_target="key",
            recommendation=(
                "Use the Authorization Code flow with PKCE for mobile OAuth. "
                "Client secrets belong on the server, not the device."
            ),
            min_value_length=5,
        ),

        # ── Generic Secret / Sensitive Keys ──────────────────────────
        SecurityRule(
            id="CRED-006",
            name="Generic Secret Value",
            description=(
                "A key suggesting sensitive or secret data was found with a "
                "non-trivial value. This may be a credential, encryption key, "
                "or other secret material."
            ),
            severity=Severity.HIGH,
            category="credentials",
            key_patterns=[
                r"secret",
                r"credential",
                r"auth",
                r"pin_code",
                r"security_answer",
                r"master_key",
            ],
            value_patterns=[],
            applies_to=_ALL_AREAS,
            match_target="key",
            recommendation=(
                "Review this value. If it is sensitive, move it to the Android "
                "Keystore or EncryptedSharedPreferences."
            ),
            min_value_length=4,
            check_entropy=True,
        ),

        # ── Session IDs ──────────────────────────────────────────────
        SecurityRule(
            id="CRED-007",
            name="Plaintext Session Identifier",
            description=(
                "A session identifier was found in plaintext storage. Session "
                "IDs allow account takeover if extracted from the device."
            ),
            severity=Severity.HIGH,
            category="session",
            key_patterns=[
                r"session[_\-]?id",
                r"session[_\-]?token",
                r"jsessionid",
                r"phpsessid",
                r"sid",
                r"cookie",
            ],
            value_patterns=[],
            applies_to=_ALL_AREAS,
            match_target="key",
            recommendation=(
                "Store session tokens in EncryptedSharedPreferences. Implement "
                "session expiry and server-side invalidation."
            ),
            min_value_length=8,
        ),

        # ── Firebase / Cloud Keys ────────────────────────────────────
        SecurityRule(
            id="CRED-008",
            name="Cloud Service Key",
            description=(
                "A cloud service key (Firebase, AWS, GCP, Azure) was found in "
                "local storage. These keys may grant access to backend "
                "infrastructure."
            ),
            severity=Severity.HIGH,
            category="credentials",
            key_patterns=[
                r"firebase[_\-]?key",
                r"firebase[_\-]?token",
                r"fcm[_\-]?token",
                r"aws[_\-]?key",
                r"aws[_\-]?secret",
                r"gcp[_\-]?key",
                r"azure[_\-]?key",
            ],
            value_patterns=[],
            applies_to=_ALL_AREAS,
            match_target="key",
            recommendation=(
                "Cloud keys should be managed server-side. Use identity "
                "federation (e.g., Firebase Auth) instead of embedding keys."
            ),
            min_value_length=10,
        ),
    ]
