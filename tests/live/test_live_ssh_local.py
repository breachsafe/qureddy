# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Live SSH coverage against the local sshd on 127.0.0.1:22.

`qureddy scan ssh` had no live test. Its classifier path is also distinct from
TLS: `ssh_algorithms.classify_offered_algorithm` calls `cipher_primitive` for
every offered cipher (`ssh_algorithms.py:143`), and nothing exercised that call
against a real KEXINIT.

macOS Remote Login is a useful endpoint for this because one scan reaches four
outcomes at once, which no public target gives us:

    mlkem768x25519-sha256        hybrid PQ key exchange, offered
    ecdh-sha2-nistp256           classical alternative, accepted
    hmac-sha1, umac-64           weak algorithms, offered
    terrapin                     posture evaluated

Assertions are structural rather than exact lists. macOS ships whatever OpenSSH
its release carries (10.2p1 when this was written), and a point upgrade adds or
drops an algorithm without changing the posture these tests describe. Asserting
"a hybrid KEX containing mlkem is offered" survives that; asserting the exact
eight-name KEX list would fail on the next OS update for no defect.

`127.0.0.1` needs no special configuration: `QUREDDY_BLOCK_INTERNAL_TARGETS` is
unset by default, so `parse_ssh_target` admits loopback. Setting it would make
every test here fail on target parsing, which is the intended signal.
"""

from __future__ import annotations

import socket
from typing import TYPE_CHECKING

import pytest

from qureddy.core.ciphers import cipher_primitive
from qureddy.core.models import AxisStatus, PqcSupport, Readiness
from qureddy.core.targets import parse_ssh_target
from qureddy.scanners.ssh.scanner import SSHScanner

if TYPE_CHECKING:
    from qureddy.core.models import ScanResult

_HOST = "127.0.0.1"
_PORT = 22
_SYMMETRIC_PRIMITIVES = frozenset({"ae", "block-cipher", "stream-cipher", "other"})


def _sshd_listening() -> bool:
    try:
        with socket.create_connection((_HOST, _PORT), timeout=3):
            return True
    except OSError:
        return False


@pytest.fixture(scope="module")
def result() -> ScanResult:
    """One scan, shared by every assertion below.

    Scoped to the module because each scan opens a real TCP connection to the
    local daemon, and every test here reads the same KEXINIT.
    """
    if not _sshd_listening():
        pytest.skip(f"no sshd on {_HOST}:{_PORT}; enable Remote Login")
    return SSHScanner().scan(parse_ssh_target(f"{_HOST}:{_PORT}", block_internal=False))


def _offered(scan: ScanResult, evidence_type: str) -> list[str]:
    return [
        e.negotiated_group or e.algorithm or ""
        for e in scan.evidence
        if e.evidence_type == evidence_type and (e.negotiated_group or e.algorithm)
    ]


def _rule_ids(scan: ScanResult) -> set[str]:
    return {f.rule_id for f in scan.findings}


def test_local_sshd_is_listening() -> None:
    """Fail, do not skip, when the local daemon is down.

    Every other test in this module skips without it, and a skipped module reads
    as a pass. This states the prerequisite so the coverage cannot silently
    disappear.
    """
    assert _sshd_listening(), (
        f"no sshd on {_HOST}:{_PORT}. Enable it with "
        "`sudo systemsetup -setremotelogin on`, or System Settings > General > "
        "Sharing > Remote Login"
    )


def test_hybrid_pq_key_exchange_is_observed(result: ScanResult) -> None:
    """OpenSSH 9.0+ offers an ML-KEM hybrid KEX, and the scanner reports it.

    This is the only PQ-positive live target in the suite. Every TLS target we
    scan is classical, so without it the hybrid-offered path has no live
    coverage at all.
    """
    kex = _offered(result, "ssh.kex")
    hybrid = [name for name in kex if "mlkem" in name.lower()]
    assert hybrid, f"no ML-KEM hybrid KEX offered; got {sorted(kex)}"
    assert "ssh.kex.hybrid_offered" in _rule_ids(result), sorted(_rule_ids(result))
    interpretation = result.summary.interpretation
    assert interpretation is not None, "scan produced no interpretation"
    axes = interpretation.axes
    assert axes.pqc_support is PqcSupport.HYBRID_OBSERVED, axes
    assert axes.key_exchange is AxisStatus.HYBRID, axes


def test_classical_alternative_is_reported_alongside_the_hybrid(result: ScanResult) -> None:
    """A hybrid offer does not clear the endpoint while ECDH is still accepted.

    The pairing is the point: hybrid_offered and classical_alternative on one
    result is what a downgrade-aware verdict has to represent, and it is the case
    a scanner that stops at the first positive would misreport.
    """
    kex = _offered(result, "ssh.kex")
    assert any("ecdh-sha2-" in name or "curve25519" in name for name in kex), sorted(kex)
    assert "ssh.kex.classical_alternative" in _rule_ids(result), sorted(_rule_ids(result))


def test_weak_transport_algorithms_are_found(result: ScanResult) -> None:
    """macOS sshd offers SHA-1 and 64-bit-tag MACs, and the scanner flags them."""
    macs = _offered(result, "ssh.mac")
    weak = [name for name in macs if "sha1" in name.lower() or "umac-64" in name.lower()]
    assert weak, f"no weak MAC offered; got {sorted(macs)}"
    assert "ssh.transport.weak" in _rule_ids(result), sorted(_rule_ids(result))
    assert result.summary.readiness is Readiness.CLASSICALLY_WEAK, result.summary.readiness


def test_every_offered_cipher_gets_a_primitive(result: ScanResult) -> None:
    """Covers `ssh_algorithms.py:143`, the SSH call into `cipher_primitive`.

    That call site is shared with the TLS emitters (#315) and had no live test.
    An SSH cipher name (aes256-ctr, chacha20-poly1305@openssh.com) is a different
    grammar from a TLS suite name, so shared code passing on TLS input proves
    nothing here.
    """
    ciphers = _offered(result, "ssh.cipher")
    assert ciphers, "no ciphers offered"
    unclassified = {
        name: cipher_primitive(name)
        for name in ciphers
        if cipher_primitive(name) not in _SYMMETRIC_PRIMITIVES
    }
    assert not unclassified, unclassified


def test_aead_ciphers_classify_as_ae(result: ScanResult) -> None:
    """GCM and ChaCha20-Poly1305 are AEAD, and must not fall through to block-cipher."""
    ciphers = _offered(result, "ssh.cipher")
    aead = [name for name in ciphers if "gcm" in name.lower() or "chacha20" in name.lower()]
    assert aead, f"no AEAD cipher offered; got {sorted(ciphers)}"
    assert {cipher_primitive(name) for name in aead} == {"ae"}, {
        name: cipher_primitive(name) for name in aead
    }


def test_host_key_and_terrapin_evidence_are_present(result: ScanResult) -> None:
    """The scan records host-key algorithms and a Terrapin posture.

    Both are SSH-only evidence types with no TLS equivalent, so this is their
    only live coverage.
    """
    assert _offered(result, "ssh.hostkey"), "no host-key algorithms recorded"
    assert any(e.evidence_type == "ssh.terrapin" for e in result.evidence), "no terrapin evidence"
    assert "ssh.terrapin.posture" in _rule_ids(result), sorted(_rule_ids(result))
