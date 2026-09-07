# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Regression: SSH PQ-hybrid KEX classification covers non-x25519 hybrids (#247).

The classifier previously matched only x25519-based hybrids, so an endpoint
offering an ML-KEM hybrid over ECDH P-256/P-384 (or a legacy Kyber hybrid) was
misread as classical and rolled up to ``quantum_vulnerable`` -- a false negative
in exactly the domain QuReddy exists to report on.
"""

from __future__ import annotations

import pytest

from qureddy.scanners.ssh.classify import pq_hybrid_kex, weak_cipher_note, weak_mac_note


@pytest.mark.parametrize(
    "kex",
    [
        "mlkem768nistp256-sha256",  # #247: ML-KEM-768 + ECDH P-256 (no x25519)
        "mlkem1024nistp384-sha384",  # #247: ML-KEM-1024 + ECDH P-384 (no x25519)
        "ecdh-nistp256-kyber-512r3-sha256-d00@openssh.com",  # legacy Kyber hybrid
        "x25519-kyber-512r3-sha256-d00@amazon.com",  # legacy AWS Kyber hybrid
        "mlkem768x25519-sha256",  # x25519 ML-KEM (already recognized)
        "sntrup761x25519-sha512",  # NTRU Prime hybrid (already recognized)
    ],
)
def test_pq_hybrid_kex_detects_every_hybrid_family(kex: str) -> None:
    assert pq_hybrid_kex((kex,)) == (kex,)


@pytest.mark.parametrize(
    "kex",
    ["curve25519-sha256", "diffie-hellman-group14-sha256", "ecdh-sha2-nistp256"],
)
def test_pq_hybrid_kex_ignores_classical(kex: str) -> None:
    assert pq_hybrid_kex((kex,)) == ()


def test_none_cipher_has_explicit_weak_note() -> None:
    """Expose the RFC-backed weakness rationale for SSH ``none``."""
    # SSH transport findings use the exact-name note map, not only the shared
    # TLS/IKE cipher weakness markers.
    assert weak_cipher_note("none") == "No encryption; NOT RECOMMENDED (RFC 4253 section 6.3)"
    assert (
        weak_mac_note("none") == "No integrity protection; NOT RECOMMENDED (RFC 4253 section 6.4)"
    )
