# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Bulk-cipher strength and CycloneDX primitive, resolved from the suite name (#315).

`cipher_classical_bits()` returns security strength per SP 800-57, so export
caps and 3DES resolve below the key their name implies. `has_weak_cipher()`
detects reviewed weak-acceptance markers independently of strength: RC4 returns
128 and still matches a weak marker. Consumers that rank or filter need both.

Matching is substring-based over the suite name, so resolution order is
significant. An export prefix has to resolve before the cipher it names, and
3DES before the "des" inside it. The three tables below encode that order;
`WEAK_CIPHER_MARKERS` is order-independent.

`cipher_classical_bits()` returns None when this table has no sourced rating. GOST
is currently unrated; future names take the same path until the registry is reviewed
(#821). The CBOM retains the observation and marks its primitive `unknown`.

This module classifies cipher families. CBOM adapters reuse its strength and primitive;
legacy findings and SSH classification reuse its primitive. Weak-marker matching is a
separate verdict.

Four protocol axes:

    observation
    ├── 1/4 key exchange  → key-exchange adapter (owned elsewhere)
    ├── 2/4 signature     → signature adapter (owned elsewhere)
    ├── 3/4 cipher suite  → this module: strength, primitive, weak verdict
    └── 4/4 digest/hash   → no owner in this module

The cipher axis has independent outputs. A cipher may have sourced strength, an
`unknown` primitive, and a weak verdict simultaneously.

CBOM projection:

    cipher observation
    ├── cipher_classical_bits() → cbom_cipher adapter → classicalSecurityLevel
    ├── cipher_primitive()      → cbom_cipher adapter → primitive
    ├── has_weak_cipher()       → legacy finding and legacy CBOM component verdict
    └── unrated suite           → component retained, strength omitted,
                                  primitive = `unknown`

Function path:

    cipher name
    ├── _sized_family_bits()    → encoded key size
    ├── _first_marker_bits()    → first ordered family match
    ├── cipher_classical_bits() → sourced strength or None
    ├── cipher_primitive()      → primitive or unknown
    └── has_weak_cipher()       → weak-acceptance-marker verdict

Forward secrecy, AEAD status, and `nistQuantumSecurityLevel` are outside this module.

These outputs are schema-constrained. `classicalSecurityLevel` is
`{"type": "integer", "minimum": 0}`. NULL receives 0. An unrated suite leaves
`classicalSecurityLevel` absent. The `primitive` enum has no member for "encrypts
nothing", so NULL maps to `other`.

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
    """Resolve a supported family-size spelling from a normalized suite name.

    Only spellings used by the supported cipher inventories are accepted. The helper
    returns ``None`` for an unrecognized spelling; callers then continue to the next
    reviewed rule. It never guesses a size from an arbitrary digit in a future name.
    """
    for size in (256, 192, 128):
        if (
            f"{family}{size}" in lowered
            or f"{family}-{size}" in lowered
            or f"{family}_{size}" in lowered
            or (
                family in lowered
                and (lowered.endswith(f"_{size}") or lowered.endswith(f"-{size}"))
            )
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

# Keep these rules ordered: NULL must become ``other`` before generic AE/block
# matching, and an unrecognized name must remain ``unknown`` rather than acquire
# a guessed primitive. The future registry will replace this transitional table.
_PRIMITIVE_RULES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("null",), "other"),
    (("gcm", "chacha20-poly1305", "ccm"), "ae"),
    (("chacha20",), "stream-cipher"),
    (("rc4", "arcfour"), "stream-cipher"),
    (
        (
            "aes",
            "camellia",
            "aria",
            "seed",
            "idea",
            "rc2",
            "des",
            "blowfish",
            "cast128",
            "twofish",
            "serpent",
            "rijndael",
            "gost2001-gost89",
            "gost94-gost89",
        ),
        "block-cipher",
    ),
)


def _first_marker_bits(lowered: str, rules: tuple[tuple[tuple[str, ...], int], ...]) -> int | None:
    """Return the first ordered rule match, preserving classification precedence.

    Export and 3DES names contain ordinary cipher markers, so callers place their
    disambiguating rules before generic family rules. ``None`` means no rule in the
    supplied table has a sourced rating.
    """
    for markers, bits in rules:
        if any(marker in lowered for marker in markers):
            return bits
    return None


def _normalise_cipher_name(name: str) -> str:
    """Canonicalize case and protocol separator spelling before classification."""
    return name.lower().replace("_", "-")


def cipher_classical_bits(name: str) -> int | None:
    """Return sourced classical strength in bits, or ``None`` without a mapping.

    ``None`` records an observed algorithm with no reviewed strength. CBOM callers
    preserve the component and omit ``classicalSecurityLevel``; they do not convert
    uncertainty into zero or a guessed value. Rule order handles export and 3DES
    names before their generic markers.
    """
    lowered = _normalise_cipher_name(name)
    bits = _first_marker_bits(lowered, _PRE_FAMILY_BITS)
    if bits is not None:
        return bits
    for family in _SIZED_FAMILIES:
        bits = _sized_family_bits(lowered, family)
        if bits is not None:
            return bits
    return _first_marker_bits(lowered, _POST_FAMILY_BITS)


def cipher_primitive(name: str) -> str:
    """Return the protocol-neutral primitive, or ``unknown`` without a mapping.

    The result is consumed by the CycloneDX adapter and SSH classification. An
    unrecognized name remains ``unknown`` so downstream CBOM output cannot imply a
    cipher family that this table did not establish.
    """
    lowered = _normalise_cipher_name(name)
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
    """Return whether accepted suite names contain a reviewed weak marker.

    This is an acceptance verdict separate from strength and primitive classification.
    A suite can have numeric strength and still return ``True``. The caller owns the
    policy response and finding text; this helper only matches the reviewed markers.
    """
    return any(
        marker in cipher.upper() for cipher in accepted_ciphers for marker in WEAK_CIPHER_MARKERS
    )
