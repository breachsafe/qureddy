# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Unit tests for the legacy TLS cipher CBOM emitter and classifier (#303).

The ``classically_weak`` branch is unreachable on the pinned OpenSSL 3.5.7 lane,
which has 3DES, RC4, and single DES compiled out. The 1.0.2u compatibility lane
negotiates them, and it is optional at runtime, so the branch is exercised here
against cipher names directly.
"""

from __future__ import annotations

import io
import json

import pytest

from qureddy.core.models import Asset, Evidence, ObservationType, Readiness, Severity
from qureddy.output import cbom_legacy
from qureddy.output.cbom import render_cbom
from qureddy.output.cbom_cipher import cipher_classical_bits, cipher_primitive
from qureddy.scanners.tls._legacy_findings import cipher_evidence_from_legacy_result
from qureddy.scanners.tls.legacy_probe import LegacyProtocolResult
from tests.test_output import _build_result


@pytest.mark.parametrize(
    ("name", "bits"),
    [
        ("ECDHE-RSA-AES256-GCM-SHA384", 256),
        ("ECDHE-RSA-AES192-CBC-SHA", 192),
        ("ECDHE-RSA-AES128-SHA", 128),
        ("DES-CBC3-SHA", 112),
        ("ECDHE-RSA-CHACHA20-POLY1305", 256),
        # Families the OpenSSL 1.0.2u compatibility lane can negotiate and the
        # 3.5.7 lane cannot. Previously all None, which dropped them from the
        # CBOM as unclassified. A rated value records them as weak.
        ("CAMELLIA128-SHA", 128),
        ("CAMELLIA256-SHA", 256),
        ("ARIA256-GCM-SHA384", 256),
        ("SEED-SHA", 128),
        ("IDEA-CBC-SHA", 128),
        ("RC4-SHA", 128),
        ("RC2-CBC-MD5", 128),
        ("DES-CBC-SHA", 56),
        # EXPORT is capped by regulation, so it must not inherit the strength of
        # the cipher it names.
        ("EXP-RC4-MD5", 40),
        ("EXP-DES-CBC-SHA", 40),
        ("EXP1024-RC4-SHA", 56),
        # A NULL suite establishes no confidentiality: zero bits, stated.
        ("NULL-MD5", 0),
        ("ECDHE-RSA-NULL-SHA", 0),
        # No primary source for GOST's classical strength, so it stays unrated.
        ("GOST2001-GOST89-GOST89", None),
        # Underscore-spelled names reach the classifier from IANA TLS suites and
        # IKEv2 transforms. _normalise_cipher_name rewrites "_" to "-", so every
        # sized-family spelling has to survive that rewrite (PR fix/cbom-classifier-pr1).
        ("TLS_AES_128_GCM_SHA256", 128),
        ("TLS_AES_256_GCM_SHA384", 256),
        ("TLS_CHACHA20_POLY1305_SHA256", 256),
        # The size is a trailing token, not adjacent to the family name.
        ("ENCR_AES_CBC_128", 128),
        ("ENCR_AES_CBC_256", 256),
        ("ENCR_AES_GCM_16_128", 128),
        ("AES_256_CBC", 256),
    ],
)
def test_legacy_cipher_bits(name: str, bits: int | None) -> None:
    assert cipher_classical_bits(name) == bits


@pytest.mark.parametrize(
    ("name", "primitive"),
    [
        ("ECDHE-RSA-AES256-GCM-SHA384", "ae"),
        ("ECDHE-RSA-CHACHA20-POLY1305", "ae"),
        ("ARIA128-GCM-SHA256", "ae"),
        ("RC4-SHA", "stream-cipher"),
        ("DES-CBC3-SHA", "block-cipher"),
        ("ECDHE-RSA-AES128-SHA", "block-cipher"),
        ("CAMELLIA256-SHA", "block-cipher"),
        ("blowfish-cbc", "block-cipher"),
        ("cast128-cbc", "block-cipher"),
        ("twofish256-cbc", "block-cipher"),
        ("serpent128-cbc", "block-cipher"),
        ("rijndael-cbc@lysator.liu.se", "block-cipher"),
        ("GOST2001-GOST89-GOST89", "block-cipher"),
        ("GOST94-GOST89-GOST89", "block-cipher"),
        ("TLS_CHACHA20_POLY1305_SHA256", "ae"),
        ("ENCR_CHACHA20_POLY1305", "ae"),
        ("chacha20", "stream-cipher"),
        ("ENCR_CHACHA20", "stream-cipher"),
        # No CycloneDX primitive describes "encrypts nothing".
        ("NULL-MD5", "other"),
        # Unknown is explicit; it is not silently promoted to block-cipher.
        ("FUTURE-CIPHER-999", "unknown"),
    ],
)
def test_legacy_cipher_primitive(name: str, primitive: str) -> None:
    """Keep primitive mapping explicit for known, NULL, and future cipher names."""
    assert cipher_primitive(name).value == primitive


def test_unrecognized_cipher_primitive_is_explicitly_unknown() -> None:
    """Prevent an unrecognized future name from receiving a fabricated primitive."""
    assert cipher_primitive("FUTURE-CIPHER-999").value == "unknown"


def test_unrecognized_tls_cipher_suite_is_retained_in_cbom() -> None:
    """Keep observed future suites visible without inventing their strength."""
    base = _build_result()
    evidence = Evidence(
        id="unknown-suite",
        asset_id=base.assets[0].id,
        evidence_type="tls.negotiation",
        observation_type=ObservationType.NEGOTIATED,
        source="qureddy.scanners.tls",
        protocol_version="TLSv1.3",
        cipher_suite="FUTURE-CIPHER-999",
        negotiated_group="X25519",
    )
    result = base.model_copy(update={"evidence": (*base.evidence, evidence)})
    stream = io.StringIO()
    render_cbom(result, stream)
    component = next(
        item
        for item in json.loads(stream.getvalue())["components"]
        if item["name"] == "FUTURE-CIPHER-999"
    )
    properties = component["cryptoProperties"]["algorithmProperties"]
    assert properties["primitive"] == "unknown"
    assert "classicalSecurityLevel" not in properties


def test_legacy_cipher_properties_carries_classical_level_never_quantum() -> None:
    props = cbom_legacy._legacy_cipher_properties("ECDHE-RSA-AES256-GCM-SHA384")  # noqa: SLF001
    assert props.primitive.value == "ae"
    assert props.classical_security_level == 256
    assert props.nist_quantum_security_level is None


def test_legacy_verdict_weak_cipher() -> None:
    verdict = {p.name: p.value for p in cbom_legacy._legacy_cipher_verdict("DES-CBC3-SHA")}  # noqa: SLF001
    assert verdict["qureddy:readiness"] == "classically_weak"
    assert verdict["qureddy:severity"] == "high"


def test_legacy_verdict_strong_classical_cipher() -> None:
    verdict = {
        p.name: p.value
        for p in cbom_legacy._legacy_cipher_verdict("ECDHE-RSA-AES256-GCM-SHA384")  # noqa: SLF001
    }
    assert verdict["qureddy:readiness"] == "quantum_vulnerable"
    assert verdict["qureddy:severity"] == "low"


def _asset() -> Asset:
    return Asset(id="asset-x", asset_type="tls.endpoint", locator="h:443", display_name="h:443")


def test_cipher_evidence_offered_emits_one_per_cipher() -> None:
    result = LegacyProtocolResult(
        protocol_flag="-tls1_2",
        protocol_version="TLSv1.2",
        offered=True,
        accepted_ciphers=("AES128-SHA", "DES-CBC3-SHA"),
    )
    evidence = cipher_evidence_from_legacy_result(_asset(), result)
    assert [e.negotiated_group for e in evidence] == ["AES128-SHA", "DES-CBC3-SHA"]
    assert [e.algorithm for e in evidence] == ["AES128-SHA", "DES-CBC3-SHA"]
    assert [e.primitive for e in evidence] == ["block-cipher", "block-cipher"]
    assert all(e.nist_quantum_security_level is None for e in evidence)
    assert all(e.evidence_type == "tls.legacy.cipher" for e in evidence)


def test_cipher_evidence_not_offered_is_empty() -> None:
    result = LegacyProtocolResult(
        protocol_flag="-tls1_1", protocol_version="TLSv1.1", offered=False, accepted_ciphers=()
    )
    assert cipher_evidence_from_legacy_result(_asset(), result) == []


def test_render_emits_legacy_cipher_components_with_verdict() -> None:
    base = _build_result()
    asset_id = base.assets[0].id
    weak = Evidence(
        id="lc-weak",
        asset_id=asset_id,
        evidence_type="tls.legacy.cipher",
        observation_type=ObservationType.OFFERED,
        source="qureddy.scanners.tls.legacy_probe",
        protocol_version="TLSv1.2",
        negotiated_group="DES-CBC3-SHA",
        notes=("accepted on TLSv1.2",),
    )
    strong = Evidence(
        id="lc-strong",
        asset_id=asset_id,
        evidence_type="tls.legacy.cipher",
        observation_type=ObservationType.OFFERED,
        source="qureddy.scanners.tls.legacy_probe",
        protocol_version="TLSv1.2",
        negotiated_group="AES256-GCM-SHA384",
        notes=("accepted on TLSv1.2",),
    )
    weak_finding = base.findings[0].model_copy(
        update={
            "id": "finding-weak",
            "evidence_ids": (weak.id,),
            "rule_id": "tls.legacy.cipher_weak",
            "finding_type": "tls.legacy.cipher_weak",
            "severity": Severity.HIGH,
            "readiness": Readiness.CLASSICALLY_WEAK,
            "protocol_version": "TLSv1.2",
            "negotiated_group": "DES-CBC3-SHA",
        }
    )
    result = base.model_copy(
        update={
            "evidence": (*base.evidence, weak, strong),
            "findings": (*base.findings, weak_finding),
        }
    )
    stream = io.StringIO()
    render_cbom(result, stream)
    components = {c["name"]: c for c in json.loads(stream.getvalue())["components"]}

    assert "DES-CBC3-SHA" in components
    assert "AES256-GCM-SHA384" in components
    weak_props = [
        (prop["name"], prop["value"])
        for prop in components["DES-CBC3-SHA"]["properties"]
        if prop["name"].startswith("qureddy:")
    ]
    assert weak_props.count(("qureddy:readiness", "classically_weak")) == 1
    assert weak_props.count(("qureddy:severity", "high")) == 1
    assert weak_props.count(("qureddy:rule_id", "tls.legacy.cipher_weak")) == 1
    strong_props = {p["name"]: p["value"] for p in components["AES256-GCM-SHA384"]["properties"]}
    assert strong_props["qureddy:readiness"] == "quantum_vulnerable"
