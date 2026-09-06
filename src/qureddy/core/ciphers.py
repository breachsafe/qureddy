# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Bulk-cipher strength and CycloneDX primitive, resolved from the suite name (#315).

`cipher_classical_bits()` returns security strength per SP 800-57, so export
caps and 3DES resolve below the key their name implies. `has_weak_cipher()` is
the prohibition signal and is independent of strength: RC4 returns 128 and is
banned. Consumers that rank or filter need both.

Matching is substring-based over the suite name, so resolution order is
significant. An export prefix has to resolve before the cipher it names, and
3DES before the "des" inside it. The three tables below encode that order;
`WEAK_CIPHER_MARKERS` is order-independent.

None means no source in this repository rates the cipher, currently GOST alone (#815).
Emit the component and leave `classicalSecurityLevel` unset.

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
        |          |            |       cbom_components:97  None DROPS the component
        |          |            |                           (TLS 1.3 AEAD path only)
        |          |            |     cbom_cipher:33  shared AlgorithmProperties
        |          |            +-> cipher_primitive()
        |          |            |     cbom_cipher:14  str -> CryptoPrimitive enum
        |          |            |     _legacy_findings:122, ssh_algorithms:143  direct
        |          |            +-> has_weak_cipher()
        |          |                  cbom_legacy:54        component verdict
        |          |                  _legacy_findings:167  scan finding
        |          +-> cbom_components:151  signature_algorithm_properties
        +-> cbom_components:131  key_exchange_algorithm_properties

Forward secrecy, AEAD status, and `nistQuantumSecurityLevel` have no owner yet.

Both return values are schema-constrained. `classicalSecurityLevel` is
`{"type": "integer", "minimum": 0}`, which is why NULL rates 0 and an unrated
cipher is omitted instead of zeroed. The `primitive` enum has no member for
"encrypts nothing", so NULL maps to `other`.

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


# Pass 1 of 3: rows that have to win against a substring of their own name.
_PRE_FAMILY_BITS: tuple[tuple[tuple[str, ...], int], ...] = (
    (("chacha20",), 256),
    (("exp1024",), 56),
    (("exp-", "export"), 40),
    (("null",), 0),  # 0, not None, so the component stays rated
    (("3des", "des-cbc3"), 112),
)

# Pass 2 of 3: size is in the name.
_SIZED_FAMILIES: tuple[str, ...] = ("aes", "camellia", "aria")

# Pass 3 of 3: one size per family. RC4 and RC2 are the non-export forms.
_POST_FAMILY_BITS: tuple[tuple[tuple[str, ...], int], ...] = (
    (("seed",), 128),
    (("idea",), 128),  # RFC 5469 s4.2 withdraws it; absent from WEAK_CIPHER_MARKERS
    (("rc4", "arcfour"), 128),
    (("rc2",), 128),
    (("des",), 56),
)

_PRIMITIVE_RULES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("null",), "other"),
    (("gcm", "chacha20-poly1305", "ccm"), "ae"),
    (("rc4", "arcfour"), "stream-cipher"),
    (("aes", "camellia", "aria", "chacha20", "seed", "idea", "rc2", "des"), "block-cipher"),
)


def _first_marker_bits(lowered: str, rules: tuple[tuple[tuple[str, ...], int], ...]) -> int | None:
    """Return the bits of the first rule whose markers appear in `lowered`."""
    for markers, bits in rules:
        if any(marker in lowered for marker in markers):
            return bits
    return None


def cipher_classical_bits(name: str) -> int | None:
    """Classical security strength in bits, or None when no source assigns one."""
    lowered = name.lower()
    bits = _first_marker_bits(lowered, _PRE_FAMILY_BITS)
    if bits is not None:
        return bits
    for family in _SIZED_FAMILIES:
        bits = _sized_family_bits(lowered, family)
        if bits is not None:
            return bits
    return _first_marker_bits(lowered, _POST_FAMILY_BITS)


def cipher_primitive(name: str) -> str:
    """Return the protocol-neutral primitive, or ``unknown`` for an unrecognized name."""
    lowered = name.lower()
    # A NULL suite encrypts nothing, so no cipher primitive describes it. The
    # CycloneDX enum has no "none" member, so "other" is the projection.
    return next(
        (
            primitive
            for markers, primitive in _PRIMITIVE_RULES
            if any(marker in lowered for marker in markers)
        ),
        "unknown",
    )


def has_weak_cipher(accepted_ciphers: tuple[str, ...]) -> bool:
    """Return whether any accepted cipher matches a known-weak marker."""
    return any(
        marker in cipher.upper() for cipher in accepted_ciphers for marker in WEAK_CIPHER_MARKERS
    )
