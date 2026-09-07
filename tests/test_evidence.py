# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Evidence builder tests for parser/probe integration.

Test path:

    fake OpenSSL transcript → ``ProbeResult`` → ``Evidence``
                                      └──────→ parser failure category
"""

from __future__ import annotations

from qureddy.core.models import FailureCategory, ProbeCommand, ProbeResult, ProbeRole, ScanTarget
from qureddy.scanners.tls._evidence import build_asset, evidence_from_probe
from qureddy.scanners.tls.openssl_probe import HYBRID_GROUP, run_hybrid_probe
from tests._fake_openssl import fake_openssl


def _target() -> ScanTarget:
    return ScanTarget(
        original_input="example.com",
        host="example.com",
        port=443,
        sni="example.com",
        locator="tls://example.com:443",
    )


def test_evidence_parser_uses_full_probe_output_not_excerpt() -> None:
    """A group line beyond EXCERPT_LIMIT must not become PARSE_NO_GROUP."""
    probe = run_hybrid_probe(
        fake_openssl("openssl_long_brief_output"),
        host="example.com",
        port=443,
        sni="example.com",
    )
    evidence = evidence_from_probe(
        asset=build_asset(_target()),
        probe=probe,
        expected_group=HYBRID_GROUP,
        probe_role=ProbeRole.HYBRID_READINESS,
    )

    assert probe.stderr_excerpt
    assert "Negotiated TLS1.3 group" not in probe.stderr_excerpt
    assert "-brief" in probe.command.args
    assert evidence.negotiated_group == HYBRID_GROUP
    assert evidence.algorithm == HYBRID_GROUP
    assert evidence.primitive == "kem"
    assert evidence.parameter_set_identifier == "ML-KEM-768"
    assert evidence.nist_quantum_security_level == 3
    assert evidence.failure_category is None


def test_evidence_parser_does_not_match_across_stream_boundary() -> None:
    """A line synthesized by stdout+stderr concatenation must not parse."""
    probe = run_hybrid_probe(
        fake_openssl("openssl_stream_boundary_phantom"),
        host="example.com",
        port=443,
        sni="example.com",
    )
    evidence = evidence_from_probe(
        asset=build_asset(_target()),
        probe=probe,
        expected_group=HYBRID_GROUP,
        probe_role=ProbeRole.HYBRID_READINESS,
    )

    assert evidence.negotiated_group is None
    assert evidence.failure_category is FailureCategory.PARSE_NO_GROUP


def test_evidence_preserves_live_handshake_details() -> None:
    """The successful probe path must project parsed details onto Evidence."""
    transcript = (
        "Protocol version: TLSv1.3\n"
        "Ciphersuite: TLS_AES_256_GCM_SHA384\n"
        "Hash used: SHA256\n"
        "Signature type: rsa_pss_rsae_sha256\n"
        "Peer Temp Key: X25519, 253 bits\n"
    )
    probe = ProbeResult(
        command=ProbeCommand(executable="openssl", args=(), timeout_seconds=30),
        return_code=0,
        stdout_sha256="0" * 64,
        stderr_sha256="0" * 64,
        parser_input=transcript,
        duration_ms=1,
    )

    evidence = evidence_from_probe(
        asset=build_asset(_target()),
        probe=probe,
        expected_group="X25519",
        probe_role=ProbeRole.CLASSICAL_CONTROL,
    )

    assert evidence.handshake_signature == "rsa_pss_rsae_sha256"
    assert evidence.handshake_hash == "SHA256"
    assert evidence.key_bits == 253


def test_real_probe_transcript_reaches_evidence_with_tls_fields() -> None:
    """The probe-to-parser seam preserves fields emitted by ``s_client -brief``."""
    probe = run_hybrid_probe(
        fake_openssl("openssl_long_brief_output"),
        host="example.com",
        port=443,
        sni="example.com",
    )

    evidence = evidence_from_probe(
        asset=build_asset(_target()),
        probe=probe,
        expected_group=HYBRID_GROUP,
        probe_role=ProbeRole.HYBRID_READINESS,
    )

    assert evidence.protocol_version == "TLSv1.3"
    assert evidence.cipher_suite == "TLS_AES_256_GCM_SHA384"
