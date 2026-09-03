# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Regression tests for independent IKE quantum and classical-hygiene findings."""

from __future__ import annotations

import pytest

from qureddy.core.models import Asset, Confidence, Evidence, ObservationType, Readiness
from qureddy.scanners.ike.classify import _finding, classify_ike


def _asset() -> Asset:
    return Asset(
        id="asset-ike",
        asset_type="ike.endpoint",
        locator="ike://vpn.example:500",
        display_name="vpn.example:500",
        protocol="ike",
    )


def _group(identifier: int, name: str, *, evidence_id: str = "ev-group") -> Evidence:
    return Evidence(
        id=evidence_id,
        asset_id="asset-ike",
        evidence_type="ike.dh_group",
        observation_type=ObservationType.OBSERVED,
        source="ike-scan/1.9.5",
        protocol="ike",
        protocol_version="IKEv2",
        algorithm=name,
        negotiated_group=name,
        ike_group_id=identifier,
        confidence=Confidence.LOW,
    )


def _algorithm(evidence_type: str, name: str) -> Evidence:
    return Evidence(
        id=f"ev-{evidence_type}-{name}",
        asset_id="asset-ike",
        evidence_type=evidence_type,
        observation_type=ObservationType.OBSERVED,
        source="ike-scan/1.9.5",
        protocol="ike",
        protocol_version="IKEv2",
        algorithm=name,
        confidence=Confidence.LOW,
    )


def test_strong_classical_group_emits_quantum_vulnerable_finding() -> None:
    """Cover issue #713 for the common modern MODP-2048 response."""
    evidence = _group(14, "2048-bit_MODP_group")

    findings = classify_ike(_asset(), [evidence])

    classical = next(item for item in findings if item.rule_id == "ike.kex.classical")
    assert classical.finding_type == "ike.kex.classical"
    assert classical.readiness is Readiness.QUANTUM_VULNERABLE
    assert classical.evidence_ids == (evidence.id,)
    assert all(item.rule_id != "ike.dh.weak" for item in findings)


def test_weak_group_emits_separate_quantum_and_hygiene_findings() -> None:
    """Keep classical weakness separate from the quantum-vulnerable axis."""
    evidence = _group(2, "1024-bit_MODP_group")

    findings = classify_ike(_asset(), [evidence])

    by_rule = {item.rule_id: item for item in findings}
    assert by_rule["ike.kex.classical"].readiness is Readiness.QUANTUM_VULNERABLE
    assert by_rule["ike.dh.weak"].readiness is Readiness.CLASSICALLY_WEAK


def test_ml_kem_identifier_never_emits_classical_finding() -> None:
    """Keep the classical path unreachable for tool-reported ML-KEM identifiers."""
    findings = classify_ike(_asset(), [_group(36, "ml-kem-768")])

    assert {item.rule_id for item in findings} == {"ike.pq.transform_reported"}
    assert findings[0].readiness is Readiness.UNKNOWN
    assert "draft-ietf-ipsecme-ikev2-mlkem-09" in findings[0].description
    assert "not an RFC" in findings[0].description


@pytest.mark.parametrize("name", ["AUTH_HMAC_MD5_96", "HMAC_MD5_96"])
def test_integrity_numeric_suffix_is_not_treated_as_cipher_key_length(name: str) -> None:
    """Preserve the IANA/ike-scan integrity transform name suffix (#724)."""
    findings = classify_ike(_asset(), [_algorithm("ike.integrity", name)])

    prohibited = next(item for item in findings if item.rule_id == "ike.transport.prohibited")
    assert prohibited.evidence_ids == (f"ev-ike.integrity-{name}",)


def test_cipher_key_length_suffix_is_removed_for_policy_matching() -> None:
    findings = classify_ike(_asset(), [_algorithm("ike.cipher", "ENCR_DES_64")])

    assert any(item.rule_id == "ike.transport.prohibited" for item in findings)


def test_protocol_identity_legacy_and_notify_findings() -> None:
    records = [
        Evidence(
            id="ev-mode",
            asset_id="asset-ike",
            evidence_type="ike.mode.responded",
            observation_type=ObservationType.OBSERVED,
            source="fixture",
            protocol="ike",
            protocol_version="IKEv2",
            confidence=Confidence.LOW,
        ),
        _algorithm("ike.cipher", "3DES"),
        Evidence(
            id="ev-identity",
            asset_id="asset-ike",
            evidence_type="ike.identity_exposed",
            observation_type=ObservationType.OBSERVED,
            source="fixture",
            protocol="ike",
            confidence=Confidence.LOW,
        ),
        Evidence(
            id="ev-psk",
            asset_id="asset-ike",
            evidence_type="ike.psk_hash_exposed",
            observation_type=ObservationType.OBSERVED,
            source="fixture",
            protocol="ike",
            protocol_version="IKEv1",
            confidence=Confidence.LOW,
        ),
        _algorithm("ike.notify", "NO_PROPOSAL_CHOSEN"),
    ]

    rules = {item.rule_id for item in classify_ike(_asset(), records)}
    assert rules == {
        "ike.v2.tool_reported",
        "ike.transport.legacy_3des",
        "ike.v1.aggressive.identity_exposed",
        "ike.v1.aggressive.psk_hash_exposed",
        "ike.proposal.rejected",
    }

    psk = next(item for item in classify_ike(_asset(), records) if item.evidence_ids == ("ev-psk",))
    assert psk.severity.value == "high"
    assert psk.readiness is Readiness.CLASSICALLY_WEAK


def test_prohibited_group_and_empty_finding_guard() -> None:
    findings = classify_ike(_asset(), [_group(1, "768-bit_MODP_group")])
    weak = next(item for item in findings if item.rule_id == "ike.dh.weak")
    assert weak.severity.value == "high"
    with pytest.raises(ValueError, match="requires evidence"):
        _finding(
            _asset(),
            [],
            rule_id="fixture",
            finding_type="fixture",
            title="fixture",
            description="fixture",
            severity=weak.severity,
            readiness=weak.readiness,
        )
