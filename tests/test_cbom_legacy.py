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
        # Families that previously returned None, so the component shipped with
        # no classicalSecurityLevel. Rating them records a strength; it does not
        # mark them weak. WEAK_CIPHER_MARKERS is unchanged, so CAMELLIA, ARIA,
        # SEED and IDEA stay quantum_vulnerable/low. Only RC4, RC2, single DES
        # and IDEA are exclusive to the 1.0.2u lane; camellia, aria and NULL are
        # in the 3.5 corpus too.
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
        # A size token in the name beats the family default (PR #824 review).
        ("RC4-64-MD5", 64),
        ("arcfour256", 256),
        ("arcfour128", 128),
        ("arcfour", 128),
        # "exp1024" is not a substring of the IANA "EXPORT1024" spelling.
        ("TLS_RSA_EXPORT1024_WITH_RC4_56_SHA", 56),
        ("TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA", 56),
        # Triple IDEA contains "idea"; no source rates it, so it must not
        # inherit IDEA's 128.
        ("ENCR_3IDEA", None),
        # An unrecognised name rates nothing rather than guessing.
        ("AES512-SHA", None),
        ("TOTALLY-UNKNOWN-CIPHER", None),
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
        # No CycloneDX primitive describes "encrypts nothing".
        ("NULL-MD5", "other"),
    ],
)
def test_legacy_cipher_primitive(name: str, primitive: str) -> None:
    assert cipher_primitive(name).value == primitive


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


def test_pass_order_is_the_correctness_property() -> None:
    """The four passes must run in order; row order inside a table is free.

    Running pass 3 before pass 1 misrates these three, so this pins the
    sequence that `cipher_classical_bits` documents (PR #824 review).
    """
    assert cipher_classical_bits("DES-CBC3-SHA") == 112, "3DES must beat the 'des' inside it"
    assert cipher_classical_bits("EXP-RC4-MD5") == 40, "export cap must beat RC4's 128"
    assert cipher_classical_bits("EXP1024-RC4-SHA") == 56, "exp1024 must beat the 40-bit cap"
