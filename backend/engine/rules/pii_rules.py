"""
SecureStorageInspector — PII Detection Rules

Detects Personally Identifiable Information stored in local storage:
email addresses, phone numbers, SSNs, credit card numbers, dates of
birth, and physical addresses.

PII in plaintext local storage violates GDPR, CCPA, and most data
protection regulations.
"""

from __future__ import annotations

from typing import List

from backend.engine.models import Severity, StorageArea
from backend.engine.rules_engine import SecurityRule


_ALL_AREAS = list(StorageArea)


def get_rules() -> List[SecurityRule]:
    """Return all PII detection rules."""
    return [
        # ── Email Address ────────────────────────────────────────────
        SecurityRule(
            id="PII-001",
            name="Email Address in Storage",
            description=(
                "An email address was detected in local storage. Email "
                "addresses are PII and should not be stored in plaintext "
                "on the device."
            ),
            severity=Severity.HIGH,
            category="pii",
            key_patterns=[
                r"email",
                r"e_mail",
                r"user_email",
                r"mail_address",
            ],
            value_patterns=[
                # Standard email pattern
                r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
            ],
            applies_to=_ALL_AREAS,
            match_target="key_or_value",
            recommendation=(
                "Avoid storing email addresses locally. If needed for display, "
                "use EncryptedSharedPreferences or mask the address (e.g., "
                "u***@example.com)."
            ),
            min_value_length=5,
        ),

        # ── Phone Number ─────────────────────────────────────────────
        SecurityRule(
            id="PII-002",
            name="Phone Number in Storage",
            description=(
                "A phone number was detected in local storage. Phone numbers "
                "are PII and can be used for social engineering or SIM-swap "
                "attacks."
            ),
            severity=Severity.HIGH,
            category="pii",
            key_patterns=[
                r"phone",
                r"mobile",
                r"cell",
                r"tel_number",
                r"phone_number",
                r"msisdn",
            ],
            value_patterns=[
                # International format: +1234567890 or variants
                r"\+?\d{1,4}[\s\-]?\(?\d{1,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{3,4}",
            ],
            applies_to=_ALL_AREAS,
            match_target="key_or_value",
            recommendation=(
                "Do not store phone numbers in plaintext. Use encrypted storage "
                "or retrieve from the server on demand."
            ),
            min_value_length=7,
        ),

        # ── SSN / National ID ────────────────────────────────────────
        SecurityRule(
            id="PII-003",
            name="SSN / National ID in Storage",
            description=(
                "A Social Security Number or national identification number "
                "was detected. This is extremely sensitive PII — storing it "
                "locally in plaintext is a critical compliance violation."
            ),
            severity=Severity.CRITICAL,
            category="pii",
            key_patterns=[
                r"ssn",
                r"social_security",
                r"national_id",
                r"tax_id",
                r"nino",  # UK National Insurance Number
                r"sin",   # Canadian Social Insurance Number
            ],
            value_patterns=[
                # US SSN: XXX-XX-XXXX
                r"\b\d{3}-\d{2}-\d{4}\b",
            ],
            applies_to=_ALL_AREAS,
            match_target="key_or_value",
            recommendation=(
                "Never store SSN/national IDs on the device. Process them "
                "server-side only and never transmit or cache locally."
            ),
            min_value_length=5,
        ),

        # ── Credit Card Number ───────────────────────────────────────
        SecurityRule(
            id="PII-004",
            name="Credit Card Number in Storage",
            description=(
                "A credit card number pattern was detected in local storage. "
                "Storing card numbers violates PCI DSS and creates serious "
                "financial risk."
            ),
            severity=Severity.CRITICAL,
            category="pii",
            key_patterns=[
                r"credit_card",
                r"card_number",
                r"card_num",
                r"cc_number",
                r"pan",
            ],
            value_patterns=[
                # Major card formats: Visa, MC, Amex, Discover
                r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))\d{8,12}\b",
                # Formatted: XXXX-XXXX-XXXX-XXXX
                r"\b\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}\b",
            ],
            applies_to=_ALL_AREAS,
            match_target="key_or_value",
            recommendation=(
                "Never store credit card numbers on the device. Use a payment "
                "gateway tokenisation service (Stripe, Braintree) that returns "
                "a non-sensitive token."
            ),
            min_value_length=13,
        ),

        # ── Date of Birth ────────────────────────────────────────────
        SecurityRule(
            id="PII-005",
            name="Date of Birth in Storage",
            description=(
                "A date-of-birth field was found in local storage. Combined "
                "with other data, DOB is a key identity verification factor."
            ),
            severity=Severity.MEDIUM,
            category="pii",
            key_patterns=[
                r"date_of_birth",
                r"dob",
                r"birth_date",
                r"birthday",
            ],
            value_patterns=[],
            applies_to=_ALL_AREAS,
            match_target="key",
            recommendation=(
                "Avoid caching date of birth locally. If needed, store only "
                "in encrypted storage."
            ),
            min_value_length=4,
        ),

        # ── Full Name ────────────────────────────────────────────────
        SecurityRule(
            id="PII-006",
            name="Full Name in Storage",
            description=(
                "A user's full name or real name was found in local storage. "
                "While lower severity alone, combined with other PII it "
                "enables identity theft."
            ),
            severity=Severity.LOW,
            category="pii",
            key_patterns=[
                r"full_name",
                r"real_name",
                r"first_name",
                r"last_name",
                r"surname",
                r"display_name",
                r"user_name",
            ],
            value_patterns=[],
            applies_to=_ALL_AREAS,
            match_target="key",
            recommendation=(
                "Consider whether caching the user's name locally is necessary. "
                "If so, use EncryptedSharedPreferences."
            ),
            min_value_length=2,
        ),

        # ── Physical Address ─────────────────────────────────────────
        SecurityRule(
            id="PII-007",
            name="Physical Address in Storage",
            description=(
                "A physical address or location data was found in local "
                "storage. Address data is protected PII under GDPR and CCPA."
            ),
            severity=Severity.MEDIUM,
            category="pii",
            key_patterns=[
                r"address",
                r"street",
                r"postal_code",
                r"zip_code",
                r"city",
                r"home_location",
                r"geo_location",
                r"latitude",
                r"longitude",
            ],
            value_patterns=[],
            applies_to=_ALL_AREAS,
            match_target="key",
            recommendation=(
                "Minimise local storage of address data. Fetch from the server "
                "when needed and do not cache."
            ),
            min_value_length=3,
        ),
    ]
