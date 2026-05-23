"""
SecureStorageInspector — Cryptographic Material Detection Rules

Detects private keys, signing keys, encryption keys, and other
cryptographic material stored in local storage. Private key exposure
is always Critical severity.
"""

from __future__ import annotations

from typing import List

from backend.engine.models import Severity, StorageArea
from backend.engine.rules_engine import SecurityRule


_ALL_AREAS = list(StorageArea)


def get_rules() -> List[SecurityRule]:
    """Return all crypto-related security rules."""
    return [
        # ── PEM Private Key ──────────────────────────────────────────
        SecurityRule(
            id="CRYPTO-001",
            name="Private Key (PEM Format)",
            description=(
                "A PEM-encoded private key was found in local storage. "
                "Private keys allow impersonation, data decryption, and "
                "signing forged requests. This is a critical finding."
            ),
            severity=Severity.CRITICAL,
            category="crypto",
            key_patterns=[],
            value_patterns=[
                r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
                r"-----BEGIN\s+EC\s+PRIVATE\s+KEY-----",
                r"-----BEGIN\s+DSA\s+PRIVATE\s+KEY-----",
                r"-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----",
                r"-----BEGIN\s+ENCRYPTED\s+PRIVATE\s+KEY-----",
            ],
            applies_to=_ALL_AREAS,
            match_target="value",
            recommendation=(
                "Never store private keys in application data. Use the "
                "Android Keystore system which stores keys in hardware-backed "
                "secure storage."
            ),
            min_value_length=20,
        ),

        # ── Private Key by Key Name ──────────────────────────────────
        SecurityRule(
            id="CRYPTO-002",
            name="Private Key Reference",
            description=(
                "A key/field name suggesting private key material was found. "
                "If this contains actual key data, it is a critical exposure."
            ),
            severity=Severity.CRITICAL,
            category="crypto",
            key_patterns=[
                r"private[_\-]?key",
                r"priv[_\-]?key",
                r"signing[_\-]?key",
                r"rsa[_\-]?key",
                r"ec[_\-]?key",
            ],
            value_patterns=[],
            applies_to=_ALL_AREAS,
            match_target="key",
            recommendation=(
                "Move private key operations to Android Keystore. The key "
                "material should never leave hardware-backed storage."
            ),
            min_value_length=10,
        ),

        # ── Encryption Key / Secret Key ──────────────────────────────
        SecurityRule(
            id="CRYPTO-003",
            name="Encryption Key in Storage",
            description=(
                "An encryption or decryption key was found in local storage. "
                "Storing encryption keys alongside encrypted data defeats "
                "the purpose of encryption."
            ),
            severity=Severity.CRITICAL,
            category="crypto",
            key_patterns=[
                r"encryption[_\-]?key",
                r"decryption[_\-]?key",
                r"aes[_\-]?key",
                r"cipher[_\-]?key",
                r"symmetric[_\-]?key",
                r"master[_\-]?key",
            ],
            value_patterns=[],
            applies_to=_ALL_AREAS,
            match_target="key",
            recommendation=(
                "Use Android Keystore to generate and store encryption keys. "
                "Keys stored alongside ciphertext provide no security."
            ),
            min_value_length=8,
            check_entropy=True,
        ),

        # ── Certificate / Public Key (lower severity) ────────────────
        SecurityRule(
            id="CRYPTO-004",
            name="Certificate or Public Key",
            description=(
                "A certificate or public key was found in local storage. "
                "While public keys are not secret, their presence may indicate "
                "custom certificate pinning that should be reviewed."
            ),
            severity=Severity.LOW,
            category="crypto",
            key_patterns=[],
            value_patterns=[
                r"-----BEGIN\s+CERTIFICATE-----",
                r"-----BEGIN\s+PUBLIC\s+KEY-----",
            ],
            applies_to=_ALL_AREAS,
            match_target="value",
            recommendation=(
                "Public keys and certificates are generally safe to store, "
                "but review if this is used for certificate pinning and ensure "
                "it is the correct, up-to-date certificate."
            ),
            min_value_length=20,
        ),

        # ── Keystore / Key File Extensions ───────────────────────────
        SecurityRule(
            id="CRYPTO-005",
            name="Keystore File Detected",
            description=(
                "A key or keystore file was found in application data. These "
                "files typically contain private keys or certificates and "
                "should not be stored in the app's data directory."
            ),
            severity=Severity.HIGH,
            category="crypto",
            key_patterns=[
                r"\.pem$",
                r"\.p12$",
                r"\.pfx$",
                r"\.key$",
                r"\.jks$",
                r"\.keystore$",
                r"\.bks$",
            ],
            value_patterns=[],
            applies_to=_ALL_AREAS,
            match_target="key",
            recommendation=(
                "Remove keystore files from application data. Use Android "
                "Keystore API for key management instead of file-based stores."
            ),
            min_value_length=0,
        ),

        # ── Hardcoded IV / Nonce ─────────────────────────────────────
        SecurityRule(
            id="CRYPTO-006",
            name="Initialization Vector / Nonce in Storage",
            description=(
                "An initialization vector (IV) or nonce was found in storage. "
                "While IVs are not secret, a static IV reused across "
                "encryptions weakens the cipher."
            ),
            severity=Severity.MEDIUM,
            category="crypto",
            key_patterns=[
                r"iv\b",
                r"init_vector",
                r"initialization_vector",
                r"nonce",
                r"salt",
            ],
            value_patterns=[],
            applies_to=_ALL_AREAS,
            match_target="key",
            recommendation=(
                "Ensure IVs/nonces are randomly generated per encryption "
                "operation, not stored and reused. If storing for decryption, "
                "verify the value changes on each write."
            ),
            min_value_length=4,
        ),
    ]
