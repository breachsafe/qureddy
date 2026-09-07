# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Classify SSH algorithm offers into PQ, classical, and weak posture.

This module is the pure classification layer between the SSH probe and the
canonical evidence/CBOM adapters. It consumes the algorithm name-lists already
collected by the probe; it does not open sockets, negotiate a session, or decide
which offered algorithm a client will select.

Classification ownership:

    SSHOffer name-list
    ├── KEX names       → shared PQ classifier + SSH weakness tables
    ├── host-key names  → shared signature classifier + SSH weakness tables
    ├── cipher names    → shared cipher primitive classifier + SSH notes
    └── MAC names       → SSH weakness table + ``mac`` primitive

The outputs are intentionally independent. A name can be structurally
classical, have a weak/deprecated rationale, and still receive a separate
CycloneDX primitive. In particular, SSH ``none`` is ``other`` with zero
classical bits in the shared cipher classifier, while this module supplies the
SSH-specific no-encryption note used by transport findings.

Posture invariants:

* every recognized PQ KEX is preserved as a hybrid candidate;
* extension and strict-KEX markers are not classified as classical fallbacks;
* unknown cipher names remain conservative through the shared classifier;
* weakness notes are exact-name mappings so stronger algorithm variants are not
  accidentally matched by a prefix.
"""

from __future__ import annotations

from types import MappingProxyType

from qureddy.core import pqc
from qureddy.core.algorithm_profile import (
    AlgorithmProfile,
    classify_key_exchange,
    classify_signature_algorithm,
)
from qureddy.core.ciphers import cipher_primitive

# PQ KEM token/category tables live in the shared qureddy.core.pqc classifier (#330), so
# TLS and SSH classify post-quantum groups through one structural source instead of copies.

# Weak/deprecated host-key algorithms, keyed to a justification note. Matched
# by exact name (not prefix) so the SHA-2 families rsa-sha2-256 / rsa-sha2-512
# and their cert variants stay OUT of this set -- only bare ssh-rsa signs with
# SHA-1. Each entry cites why the algorithm is weak or deprecated.
_WEAK_HOST_KEY_NOTES = MappingProxyType(
    {
        # DSA is fixed at 1024-bit and disabled by default since OpenSSH 7.0.
        "ssh-dss": "DSA host key (1024-bit, deprecated; off by default since OpenSSH 7.0)",
        "ssh-dss-cert-v01@openssh.com": "DSA certificate host key (1024-bit, deprecated)",
        # ssh-rsa signs with SHA-1 (RFC 8332); disabled by default since OpenSSH 8.8.
        "ssh-rsa": "RSA host key with SHA-1 signature (RFC 8332; off by default since OpenSSH 8.8)",
        "ssh-rsa-cert-v01@openssh.com": "RSA certificate host key with SHA-1 signature (RFC 8332)",
    }
)
_WEAK_HOST_KEYS = frozenset(_WEAK_HOST_KEY_NOTES)
# All current SSH host-key signature families are classical (no ML-DSA/SLH-DSA
# host-key type exists in OpenSSH as of this writing).
_CLASSICAL_HOST_KEY_PREFIXES = ("ssh-ed25519", "ecdsa-sha2-", "ssh-rsa", "rsa-sha2-", "ssh-dss")

# Weak/deprecated key-exchange algorithms, keyed to a justification note. Matched
# by exact name (the scanner already collects the offered KEX name-list, so this
# reads what the probe has, no new collection). ssh-audit fails/warns on these
# small-group or SHA-1 key exchanges; each entry cites why it is weak.
_WEAK_KEX_NOTES = MappingProxyType(
    {
        # 1024-bit MODP group (Oakley group 2) plus a SHA-1 hash.
        "diffie-hellman-group1-sha1": (
            "1024-bit MODP group (Oakley group 2) with SHA-1 (RFC 4253; "
            "off by default since OpenSSH 7.0)"
        ),
        # 2048-bit group but a deprecated SHA-1 hash; SHA-2 variant preferred.
        "diffie-hellman-group14-sha1": "SHA-1 key-exchange hash (RFC 8268 prefers the SHA-2 variant)",
        # Group-exchange with a SHA-1 hash; disabled by default in modern OpenSSH.
        "diffie-hellman-group-exchange-sha1": (
            "SHA-1 key-exchange hash (off by default in modern OpenSSH)"
        ),
        # 1024-bit RSA transport key with a SHA-1 hash (RFC 4432).
        "rsa1024-sha1": "1024-bit RSA transport key with SHA-1 (RFC 4432)",
    }
)
_WEAK_KEX = frozenset(_WEAK_KEX_NOTES)

# Weak/deprecated SSH transport ciphers, keyed to a justification note. Names are the
# SSH cipher identifiers (RFC 4253/4344, OpenSSH). Matched by exact name. Keep ``none``
# here as well as in the shared classifier because SSH findings use this note map.
_WEAK_CIPHER_NOTES = MappingProxyType(
    {
        "none": "No encryption; NOT RECOMMENDED (RFC 4253 section 6.3)",
        "3des-cbc": "3DES: 64-bit block (SWEET32, RFC 7465-class); deprecated",
        "arcfour": "RC4 stream cipher (broken; removed from OpenSSH 7.6)",
        "arcfour128": "RC4 stream cipher (broken)",
        "arcfour256": "RC4 stream cipher (broken)",
        "blowfish-cbc": "Blowfish 64-bit block (deprecated)",
        "cast128-cbc": "CAST-128 64-bit block (deprecated)",
        "aes128-cbc": "CBC mode (RFC 4344 prefers CTR/GCM; plaintext-recovery risk)",
        "aes192-cbc": "CBC mode (RFC 4344 prefers CTR/GCM)",
        "aes256-cbc": "CBC mode (RFC 4344 prefers CTR/GCM)",
    }
)
# Weak/deprecated SSH MACs. HMAC-MD5 and HMAC-SHA1 (and their -96 truncations) rely on
# broken/deprecated hashes; Encrypt-then-MAC variants share the same underlying weakness.
_WEAK_MAC_NOTES = MappingProxyType(
    {
        "hmac-md5": "HMAC-MD5 (broken hash)",
        "hmac-md5-96": "HMAC-MD5, 96-bit tag (broken hash)",
        "hmac-md5-etm@openssh.com": "HMAC-MD5 (broken hash)",
        "none": "No integrity protection; NOT RECOMMENDED (RFC 4253 section 6.4)",
        "hmac-sha1": "HMAC-SHA1 (deprecated; SHA-1 collisions)",
        "hmac-sha1-96": "HMAC-SHA1, 96-bit tag (deprecated)",
        "hmac-sha1-etm@openssh.com": "HMAC-SHA1 (deprecated)",
        "umac-64@openssh.com": "64-bit UMAC tag (short; 128-bit preferred)",
    }
)

_TERRAPIN_CHACHA20 = "chacha20-poly1305@openssh.com"

KexClass = AlgorithmProfile


def terrapin_susceptible_modes(ciphers: tuple[str, ...], macs: tuple[str, ...]) -> tuple[str, ...]:
    """Return offered cipher/MAC combinations relevant to the Terrapin attack surface.

    ChaCha20-Poly1305 is reported independently. CBC modes are reported only when an
    encrypt-then-MAC offer exists, because a CBC cipher by itself is not the issue's
    Terrapin combination.
    """
    modes = [name for name in ciphers if name == _TERRAPIN_CHACHA20]
    etm_macs = tuple(name for name in macs if name.endswith("-etm@openssh.com"))
    modes.extend(
        f"{cipher} + {mac}" for cipher in ciphers if cipher.endswith("-cbc") for mac in etm_macs
    )
    return tuple(modes)


def weak_cipher_note(name: str) -> str | None:
    """Justification note if the SSH cipher is weak/deprecated, else None."""
    return _WEAK_CIPHER_NOTES.get(name)


def weak_mac_note(name: str) -> str | None:
    """Justification note if the SSH MAC is weak/deprecated, else None."""
    return _WEAK_MAC_NOTES.get(name)


def is_pq_hybrid_kex(name: str) -> bool:
    """True if a KEX name carries any post-quantum KEM (structural; shared classifier, #330)."""
    return pqc.is_pq_kem(name)


def pq_hybrid_kex(offer_kex: tuple[str, ...]) -> tuple[str, ...]:
    """The PQ-hybrid KEX algorithms the server offers (may be empty)."""
    return tuple(a for a in offer_kex if is_pq_hybrid_kex(a))


def classify_kex(name: str) -> KexClass | None:
    """Preserve the SSH classifier API through the protocol-neutral owner."""
    return classify_key_exchange(name)


def classify_offered_algorithm(evidence_type: str, name: str) -> AlgorithmProfile | None:
    """Classify one named SSH offer for the canonical evidence model."""
    if evidence_type in {"ssh.kex", "ssh.kex.weak"}:
        return classify_key_exchange(name)
    if evidence_type == "ssh.hostkey":
        return classify_signature_algorithm(name)
    if evidence_type == "ssh.cipher":
        return AlgorithmProfile(cipher_primitive(name), None)
    if evidence_type == "ssh.mac":
        return AlgorithmProfile("mac", None)
    return None


_PSEUDO_KEX_MARKERS = ("ext-info-", "kex-strict-")


def is_classical_kex(name: str) -> bool:
    """Return whether ``name`` is a classical KEX alternative (fail-safe).

    SSH KEX name-lists also carry extension/strict-KEX markers. Everything
    else that is not a recognized PQ hybrid is treated as classical for
    downgrade posture; CBOM profiling remains conservative in ``classify_kex``.
    """
    lowered = name.lower()
    return not (is_pq_hybrid_kex(name) or lowered.startswith(_PSEUDO_KEX_MARKERS))


def weak_host_keys(offer_host_keys: tuple[str, ...]) -> tuple[str, ...]:
    """Deprecated/weak host-key algorithms offered (e.g. ssh-dss, ssh-rsa)."""
    return tuple(a for a in offer_host_keys if a in _WEAK_HOST_KEYS)


def weak_host_key_note(algorithm: str) -> str | None:
    """The weakness justification for one host-key algorithm, or None if not weak."""
    return _WEAK_HOST_KEY_NOTES.get(algorithm)


def weak_kex(offer_kex: tuple[str, ...]) -> tuple[str, ...]:
    """Deprecated/weak key-exchange algorithms offered (e.g. diffie-hellman-group1-sha1)."""
    return tuple(a for a in offer_kex if a in _WEAK_KEX)


def weak_kex_reasons(offer_kex: tuple[str, ...]) -> tuple[str, ...]:
    """One 'name: reason' note per weak key-exchange algorithm offered, for reporting."""
    return tuple(f"{a}: {_WEAK_KEX_NOTES[a]}" for a in offer_kex if a in _WEAK_KEX)
