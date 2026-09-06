# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Bulk-cipher strength and CycloneDX primitive, resolved from the suite name (#315).

`cipher_classical_bits()` returns SP 800-57 Table 2 security strength where NIST
defines one, which is AES and 3DES. For every other family it returns the key
length the name carries, capped by export policy. NIST assigns no strength to
RC4, RC2, IDEA, SEED, Camellia or ARIA, so treat those figures as key length.

`has_weak_cipher()` is the prohibition signal and is independent of strength:
RC4 returns 128 and is banned. Consumers that rank or filter need both.

Matching is substring-based, so pass order carries the correctness. The order
lives in `cipher_classical_bits()`. Row order inside a single table is free:
every permutation gives the same answer, while reversing the passes misrates
DES-CBC3-SHA, EXP-RC4-MD5 and EXP1024-RC4-SHA. `WEAK_CIPHER_MARKERS` is
order-independent.

None means the name is unrecognised, or recognised with no sourced strength.
Callers emit the component and leave `classicalSecurityLevel` unset. Among TLS
suites the shipped runtimes offer, GOST is the only unrated family; the SSH and
IKE surfaces also reach blowfish, cast128, twofish, serpent, RC5 and a
size-less `ENCR_AES_CBC` (#815).

One axis of four, and where each return value lands. CBOM callers reach the
first two through the cbom_cipher adapter, which maps the primitive string to
the CycloneDX enum. Scanner callers import from here directly.

      ECDHE   -   RSA   -   AES128GCM   -   SHA256
        |          |            |               |
       kx         sig      this module      unmodelled
        |          |            |
        |          |            +-> cipher_classical_bits()
        |          |            |     cbom_cipher:13  re-export, value unchanged
        |          |            |       cbom_legacy:42      None passes through
        |          |            |       cbom_components:97  None omits the whole
        |          |            |                           algorithmProperties, losing
        |          |            |                           the primitive too. The
        |          |            |                           component still ships.
        |          |            |                           (TLS 1.3 AEAD path only)
        |          |            |     cbom_cipher:33  shared AlgorithmProperties, and
        |          |            |                     the callable cbom_ssh:138 and
        |          |            |                     cbom_ike:28 hand to the emitter
        |          |            +-> cipher_primitive()
        |          |            |     cbom_cipher:26  str -> CryptoPrimitive enum
        |          |            |     _legacy_findings:122, ssh_algorithms:143  direct
        |          |            +-> has_weak_cipher()
        |          |                  cbom_legacy:54        component verdict
        |          |                  _legacy_findings:167  scan finding
        |          +-> cbom_components:151  signature_algorithm_properties
        +-> cbom_components:131  key_exchange_algorithm_properties

Forward secrecy, AEAD status, and `nistQuantumSecurityLevel` have no owner yet.

Both return values are schema-constrained. `classicalSecurityLevel` is
`{"type": "integer", "minimum": 0}` and optional. 0 is therefore legal for NULL,
which provides zero confidentiality, and an unrated cipher omits the field
because the type admits no null. The `primitive` enum carries both `other` and
`unknown` and no member for "encrypts nothing". NULL maps to `other`, since the
schema defines `unknown` as "the primitive is not known" and a NULL suite is
known.

    SP 800-57 Pt 1 Rev 5  https://doi.org/10.6028/NIST.SP.800-57pt1r5
    RFC 7465 s2           https://www.rfc-editor.org/rfc/rfc7465#section-2
    RFC 5469 s4           https://www.rfc-editor.org/rfc/rfc5469#section-4
    CycloneDX 1.7         https://cyclonedx.org/docs/1.7/
    Rating policy         docs/architecture/weak-cipher-classification-adr.md
"""

from __future__ import annotations

WEAK_CIPHER_MARKERS: tuple[str, ...] = (
    "3DES",
    "DES",
    "RC4",
    "RC2",
    "NULL",
    "EXPORT",
    "MD5",
    "ADH",
    "AECDH",
)


def _sized_family_bits(lowered: str, family: str) -> int | None:
    """Return the key size for a family whose name carries it (aes128, aria-256)."""
    for size in (256, 192, 128):
        if (
            f"{family}{size}" in lowered
            or f"{family}-{size}" in lowered
            or f"{family}_{size}" in lowered
            or (family in lowered and lowered.endswith(f"_{size}"))
        ):
            return size
    return None


# Pass 0 of 4: names we can identify and have no sourced strength for. Checked
# first so no substring rule below can claim them. `3idea` contains `idea`.
_UNRATED_MARKERS: tuple[str, ...] = ("3idea",)

# Pass 1 of 4: rows that have to win against a substring of their own name.
_PRE_FAMILY_BITS: tuple[tuple[tuple[str, ...], int], ...] = (
    (("chacha20",), 256),
    (("rc4-64", "rc4_64"), 64),  # before the generic rc4 row in pass 3
    (("exp1024", "export1024"), 56),  # "exp1024" is not a substring of "export1024"
    (("exp-", "export"), 40),
    (("null",), 0),  # zero bits keeps the component rated
    (("3des", "des-cbc3"), 112),
)

# Pass 2 of 4: size is in the name. arcfour256 and arcfour128 differ.
_SIZED_FAMILIES: tuple[str, ...] = ("aes", "camellia", "aria", "arcfour")

# Pass 3 of 4: one size per family. RC4 and RC2 are the non-export forms.
_POST_FAMILY_BITS: tuple[tuple[tuple[str, ...], int], ...] = (
    (("seed",), 128),
    (("idea",), 128),  # RFC 5469 s4.2 deprecates it and states the 128-bit key
    (("rc4", "arcfour"), 128),
    (("rc2",), 128),
    (("des",), 56),
)


def _first_marker_bits(lowered: str, rules: tuple[tuple[tuple[str, ...], int], ...]) -> int | None:
    """Return the bits of the first rule whose markers appear in `lowered`."""
    for markers, bits in rules:
        if any(marker in lowered for marker in markers):
            return bits
    return None


def cipher_classical_bits(name: str) -> int | None:
    """Classical security strength in bits, or None when no source assigns one.

    Pass order carries the correctness. Reversing these four passes misrates
    DES-CBC3-SHA, EXP-RC4-MD5 and EXP1024-RC4-SHA. Row order inside a single
    table is free; every permutation gives the same answer.
    """
    lowered = name.lower()
    if any(marker in lowered for marker in _UNRATED_MARKERS):
        return None
    bits = _first_marker_bits(lowered, _PRE_FAMILY_BITS)
    if bits is not None:
        return bits
    for family in _SIZED_FAMILIES:
        bits = _sized_family_bits(lowered, family)
        if bits is not None:
            return bits
    return _first_marker_bits(lowered, _POST_FAMILY_BITS)


def cipher_primitive(name: str) -> str:
    """Return the protocol-neutral primitive vocabulary for a symmetric cipher."""
    lowered = name.lower()
    # A NULL suite encrypts nothing, so no cipher primitive describes it. The
    # CycloneDX enum has no "none" member, so "other" is the projection.
    if "null" in lowered:
        return "other"
    if "gcm" in lowered or "chacha20-poly1305" in lowered or "ccm" in lowered:
        return "ae"
    if "rc4" in lowered or "arcfour" in lowered:
        return "stream-cipher"
    return "block-cipher"


def has_weak_cipher(accepted_ciphers: tuple[str, ...]) -> bool:
    """Return whether any accepted cipher matches a known-weak marker."""
    return any(
        marker in cipher.upper() for cipher in accepted_ciphers for marker in WEAK_CIPHER_MARKERS
    )
