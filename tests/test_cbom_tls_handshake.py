# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""JSON and CBOM parity tests for live TLS handshake details.

Test path:

    probe transcript → parsed Evidence → ScanResult → CycloneDX CBOM
                              └──────────────→ TLS fields and cipher asset
"""

from __future__ import annotations

from pathlib import Path

import pytest

from qureddy.core.certificate import CertificateObservation
from qureddy.core.errors import CbomError
from qureddy.core.models import Evidence, ObservationType, ProbeRole, ScanResult
from qureddy.output.cbom_semantics import validate_cbom_semantics
from qureddy.scanners.tls._evidence import build_asset, evidence_from_probe
from qureddy.scanners.tls.openssl_probe import HYBRID_GROUP, run_hybrid_probe
from qureddy.scanners.tls.parse import parse_brief_output
from tests._cbom_fixtures import _build_result, _render
from tests._fake_openssl import fake_openssl
from tests.conformance.harness import official_errors, semantic_errors

FIXTURES = Path(__file__).parent / "fixtures" / "openssl"


def _result_with_handshake_details() -> ScanResult:
    result = _build_result()
    evidence = Evidence(
        id="ev-live-auth",
        asset_id="asset-1",
        evidence_type="tls.negotiation",
        observation_type=ObservationType.NEGOTIATED,
        source="qureddy.scanners.tls.parse",
        protocol_version="TLSv1.3",
        cipher_suite="TLS_AES_256_GCM_SHA384",
        negotiated_group="X25519",
        handshake_signature="rsa_pss_rsae_sha256",
        handshake_hash="SHA256",
        key_bits=253,
    )
    return result.model_copy(update={"evidence": (evidence,)})


def _real_mldsa_result() -> ScanResult:
    """Build a complete CBOM input from the captured ML-DSA-65 handshake."""
    raw = (FIXTURES / "brief_pq_local_mldsa65.txt").read_text(encoding="utf-8")
    stdout = "\n".join(line for line in raw.splitlines() if not line.lstrip().startswith("#"))
    parsed = parse_brief_output(stdout, expected_group="X25519MLKEM768")
    result = _build_result()
    handshake = result.evidence[0].model_copy(
        update={
            "id": "ev-live-auth",
            "handshake_signature": parsed.handshake_signature,
            "handshake_hash": parsed.handshake_hash,
        }
    )
    certificate = CertificateObservation(
        subject="CN=hello-pqc.local",
        issuer="CN=hello-pqc.local",
        not_before="Sep 5 07:00:00 2026 GMT",
        not_after="Sep 5 07:00:00 2027 GMT",
        serial="01",
        signature_algorithm="ML-DSA-65",
        public_key_summary="Public Key Algorithm: ML-DSA-65",
        public_key_algorithm="ML-DSA-65",
        is_self_signed=True,
        is_post_quantum_signature=True,
    )
    certificate_evidence = Evidence(
        id="ev-cert",
        asset_id="asset-1",
        evidence_type="tls.cert.signature",
        observation_type=ObservationType.OBSERVED,
        source="qureddy.scanners.tls.cert_sig",
        certificate_record=certificate,
    )
    return result.model_copy(update={"evidence": (handshake, certificate_evidence)})


def test_json_evidence_exposes_live_handshake_details() -> None:
    result = _result_with_handshake_details()
    evidence = result.model_dump(mode="json")["evidence"][0]

    assert evidence["handshake_signature"] == "rsa_pss_rsae_sha256"
    assert evidence["handshake_hash"] == "SHA256"
    assert evidence["key_bits"] == 253


def test_cbom_emits_live_certificate_verify_signature() -> None:
    payload = _render(_result_with_handshake_details())
    component = next(
        item for item in payload["components"] if item["name"] == "rsa_pss_rsae_sha256"
    )
    properties = {item["name"]: item["value"] for item in component["properties"]}

    assert component["cryptoProperties"]["algorithmProperties"]["primitive"] == "signature"
    assert properties["qureddy:signature.role"] == "tls.handshake.certificate_verify"
    assert properties["qureddy:signature.hash"] == "SHA256"


def test_live_probe_fields_reach_tls_cipher_suite_cbom_asset() -> None:
    """A parsed probe result produces the negotiated suite in the CBOM."""
    result = _build_result()
    probe = run_hybrid_probe(
        fake_openssl("openssl_long_brief_output"),
        host="example.com",
        port=443,
        sni="example.com",
    )
    evidence = evidence_from_probe(
        asset=build_asset(result.target),
        probe=probe,
        expected_group=HYBRID_GROUP,
        probe_role=ProbeRole.HYBRID_READINESS,
    )

    payload = _render(result.model_copy(update={"evidence": (evidence,)}))
    component = next(
        item for item in payload["components"] if item["name"] == "TLS_AES_256_GCM_SHA384"
    )

    assert evidence.protocol_version == "TLSv1.3"
    assert evidence.cipher_suite == component["name"]


def test_real_mldsa_handshake_alias_reuses_canonical_certificate_component() -> None:
    result = _real_mldsa_result()

    payload = _render(result)
    algorithms = [
        item for item in payload["components"] if item["bom-ref"] == "crypto/algorithm/ml-dsa-65"
    ]

    assert result.evidence[0].handshake_signature == "ML-DSA-65"
    assert len(algorithms) == 1
    properties = algorithms[0]["cryptoProperties"]["algorithmProperties"]
    assert properties["parameterSetIdentifier"] == "ML-DSA-65"
    assert properties["nistQuantumSecurityLevel"] == 3
    assert not any(item["bom-ref"] == "crypto/algorithm/mldsa65" for item in payload["components"])


@pytest.mark.parametrize(
    ("openssl_name", "canonical_name"),
    [("mldsa44", "ML-DSA-44"), ("mldsa65", "ML-DSA-65"), ("mldsa87", "ML-DSA-87")],
)
def test_openssl_mldsa_handshake_aliases_are_canonicalized(
    openssl_name: str, canonical_name: str
) -> None:
    stdout = f"Peer Temp Key: X25519, 253 bits\nSignature type: {openssl_name}\n"

    parsed = parse_brief_output(stdout, expected_group="X25519")

    assert parsed.handshake_signature == canonical_name


def test_classical_dsa_handshake_name_is_preserved() -> None:
    stdout = "Peer Temp Key: X25519, 253 bits\nSignature type: dsa_sha256\n"
    parsed = parse_brief_output(stdout, expected_group="X25519")
    result = _result_with_handshake_details()
    evidence = result.evidence[0].model_copy(
        update={"handshake_signature": parsed.handshake_signature}
    )

    payload = _render(result.model_copy(update={"evidence": (evidence,)}))
    component = next(item for item in payload["components"] if item["name"] == "dsa_sha256")
    assert parsed.handshake_signature == "dsa_sha256"
    assert component["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 0


def test_cbom_emits_ephemeral_public_key_material() -> None:
    payload = _render(_result_with_handshake_details())
    component = next(
        item
        for item in payload["components"]
        if item["cryptoProperties"]["assetType"] == "related-crypto-material"
    )
    material = component["cryptoProperties"]["relatedCryptoMaterialProperties"]

    assert material["type"] == "public-key"
    assert material["algorithmRef"] == "crypto/algorithm/x25519"
    assert material["size"] == 253
    assert material["state"] == "active"


def test_duplicate_ephemeral_observations_emit_one_material_asset() -> None:
    result = _result_with_handshake_details()
    duplicate = result.evidence[0].model_copy(update={"id": "ev-live-auth-2"})

    payload = _render(result.model_copy(update={"evidence": (*result.evidence, duplicate)}))
    materials = [
        item
        for item in payload["components"]
        if item["cryptoProperties"]["assetType"] == "related-crypto-material"
    ]

    assert len(materials) == 1


def test_handshake_cbom_passes_official_and_semantic_validation() -> None:
    payload = _render(_result_with_handshake_details())

    assert not official_errors(payload)
    assert not semantic_errors(payload)


def test_runtime_guard_rejects_dangling_ephemeral_algorithm_reference() -> None:
    payload = _render(_result_with_handshake_details())
    material = next(
        item
        for item in payload["components"]
        if item["cryptoProperties"]["assetType"] == "related-crypto-material"
    )
    material["cryptoProperties"]["relatedCryptoMaterialProperties"]["algorithmRef"] = (
        "crypto/algorithm/missing"
    )

    with pytest.raises(CbomError, match="dangling references"):
        validate_cbom_semantics(payload)
