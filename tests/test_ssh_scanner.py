# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Tests for SSH posture classification and readiness rollup."""

from __future__ import annotations

import io
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from qureddy.core.models import HndlExposure, Readiness
from qureddy.core.targets import parse_ssh_target
from qureddy.output.cbom import render_cbom
from qureddy.output.console import render_rich
from qureddy.scanners.ssh import classify
from qureddy.scanners.ssh.probe import SSHOffer, SSHServerIdentity
from qureddy.scanners.ssh.scanner import scan_ssh


def _run(
    kex: tuple[str, ...],
    host_keys: tuple[str, ...],
    *,
    ciphers: tuple[str, ...] = (),
    macs: tuple[str, ...] = (),
    strict_kex: bool = False,
    server_identity: SSHServerIdentity | None = None,
):
    offer = SSHOffer(
        server_banner="SSH-2.0-test",
        kex_algorithms=kex,
        host_key_algorithms=host_keys,
        ciphers=ciphers,
        macs=macs,
        strict_kex=strict_kex,
        server_identity=server_identity,
    )
    target = parse_ssh_target("test.invalid")
    with patch("qureddy.scanners.ssh.scanner.read_kexinit_offer", return_value=offer):
        return scan_ssh(target, timeout_seconds=1)


def test_pq_hybrid_offered_is_transitional_hybrid() -> None:
    r = _run(("mlkem768x25519-sha256", "curve25519-sha256"), ("ssh-ed25519",))
    assert r.summary.readiness is Readiness.TRANSITIONAL_HYBRID
    finding = next(f for f in r.findings if f.rule_id == "ssh.kex.hybrid_offered")
    assert finding.primitive == "kem"
    assert finding.nist_quantum_security_level == 3


def test_pq_hybrid_with_classical_fallback_is_defeasible() -> None:
    result = _run(
        (
            "sntrup761x25519-sha512@openssh.com",
            "curve25519-sha256",
            "ecdh-sha2-nistp256",
        ),
        ("ssh-ed25519",),
    )

    rules = {finding.rule_id for finding in result.findings}
    assert "ssh.kex.hybrid_offered" in rules
    assert "ssh.kex.classical_alternative" in rules
    assert result.summary.interpretation.hndl_exposure is HndlExposure.PROTECTED_DEFEASIBLE
    assert "classical_kex_negotiated" in result.summary.interpretation.reason_codes
    assert "Classical alternative accepted: curve25519-sha256" in (
        result.summary.interpretation.display.evaluation.observed_facts
    )
    classical = next(
        finding for finding in result.findings if finding.rule_id == "ssh.kex.classical_alternative"
    )
    assert classical.primitive == "key-agree"
    assert classical.nist_quantum_security_level == 0


@pytest.mark.parametrize("marker", ["ext-info-c", "kex-strict-c-v00@openssh.com"])
def test_kex_pseudo_marker_is_not_reported_as_classical_downgrade(marker: str) -> None:
    result = _run(
        ("mlkem768x25519-sha256", marker),
        ("ssh-ed25519",),
    )

    rules = {finding.rule_id for finding in result.findings}
    assert "ssh.kex.hybrid_offered" in rules
    assert "ssh.kex.classical_alternative" not in rules
    assert result.summary.interpretation.hndl_exposure is HndlExposure.PROTECTED


@pytest.mark.parametrize(
    "classical_kex", ["gss-group14-sha256-", "gss-group14-sha1-", "curve448-sha512"]
)
def test_unrecognized_classical_kex_is_reported_as_downgrade(classical_kex: str) -> None:
    result = _run(("mlkem768x25519-sha256", classical_kex), ("ssh-ed25519",))

    rules = {finding.rule_id for finding in result.findings}
    assert "ssh.kex.hybrid_offered" in rules
    assert "ssh.kex.classical_alternative" in rules
    assert result.summary.interpretation.hndl_exposure is HndlExposure.PROTECTED_DEFEASIBLE


def test_classical_only_is_quantum_vulnerable() -> None:
    r = _run(("curve25519-sha256", "ecdh-sha2-nistp256"), ("ssh-ed25519",))
    assert r.summary.readiness is Readiness.QUANTUM_VULNERABLE
    finding = next(f for f in r.findings if f.rule_id == "ssh.kex.classical_only")
    assert finding.algorithm is None
    assert finding.primitive is None
    assert finding.nist_quantum_security_level is None


def test_weak_hostkey_rolls_up_to_classically_weak() -> None:
    # PQ hybrid offered BUT weak ssh-dss host key -> classically_weak wins
    r = _run(("mlkem768x25519-sha256",), ("ssh-dss", "ssh-ed25519"))
    assert r.summary.readiness is Readiness.CLASSICALLY_WEAK
    assert r.summary.interpretation.effective is Readiness.CLASSICALLY_WEAK
    rules = {f.rule_id for f in r.findings}
    assert "ssh.kex.hybrid_offered" in rules
    assert "ssh.hostkey.weak" in rules


def test_scanner_name_and_scheme() -> None:
    r = _run(("mlkem768x25519-sha256",), ("ssh-ed25519",))
    assert r.scan.scanner_name == "ssh"
    assert r.target.scheme == "ssh"
    assert r.target.locator.startswith("ssh://")
    assert r.dependencies == ()  # SSH has no openssl dependency


def test_weak_ssh_algorithm_is_visible_in_ciso_evaluation() -> None:
    result = _run(("mlkem768x25519-sha256",), ("ssh-rsa",))
    evaluation = result.summary.interpretation.display.evaluation
    assert result.summary.interpretation.hygiene_status.value == "weak"
    assert evaluation.hardening == "Protocol hardening is required"
    assert "SSH weak algorithm offered: ssh-rsa" in evaluation.observed_facts


def test_server_identity_is_typed_evidence_and_cbom_endpoint_property() -> None:
    result = _run(
        ("curve25519-sha256",),
        ("ssh-ed25519",),
        server_identity=SSHServerIdentity(software="OpenSSH", version="9.6p1"),
    )
    evidence = next(e for e in result.evidence if e.evidence_type == "ssh.server")
    assert (evidence.server_software, evidence.server_version) == ("OpenSSH", "9.6p1")
    stream = io.StringIO()
    render_cbom(result, stream)
    properties = {
        item["name"]: item["value"]
        for item in json.loads(stream.getvalue())["metadata"]["component"].get("properties", [])
    }
    assert properties["qureddy:ssh.server.software"] == "OpenSSH"
    assert properties["qureddy:ssh.server.version"] == "9.6p1"
    assert result.summary.readiness is Readiness.QUANTUM_VULNERABLE


def test_sntrup_also_counts_as_hybrid() -> None:
    r = _run(("sntrup761x25519-sha512@openssh.com", "curve25519-sha256"), ("ssh-ed25519",))
    assert r.summary.readiness is Readiness.TRANSITIONAL_HYBRID


def test_captured_ssh_cbom_fixtures_carry_full_inventory() -> None:
    """The REAL captured SSH CBOMs carry the full crypto inventory (#243/#245).

    Validates the conformance fixtures produced by the real CLI against live servers
    (github.com = sntrup761 hybrid, gitlab.com = ML-KEM hybrid) — not a hand-built fake
    offer. Every fixture must inventory host keys (signature), each KEX group (kem +
    key-agree), and the transport ciphers/MACs (ae/block-cipher + mac) the CBOM used to
    drop.
    """
    fixtures = Path(__file__).parent / "conformance" / "fixtures" / "positive"
    for name in ("p3-ssh-hybrid", "p3-ssh-mlkem"):
        payload = json.loads((fixtures / f"{name}.cbom.json").read_text())
        assert payload["specVersion"] == "1.7"
        primitives = {
            (c.get("cryptoProperties", {}).get("algorithmProperties") or {}).get("primitive")
            for c in payload["components"]
        }
        assert "signature" in primitives, f"{name}: host-key signature asset missing"
        assert "kem" in primitives, f"{name}: PQ-hybrid KEX (kem) asset missing"
        assert "key-agree" in primitives, f"{name}: classical KEX asset missing"
        assert "mac" in primitives, f"{name}: MAC asset missing (#243)"
        assert primitives & {"ae", "block-cipher", "stream-cipher"}, (
            f"{name}: cipher asset missing (#243)"
        )


def test_ssh_rsa_sha1_hostkey_flagged_weak() -> None:
    # A2/#143: ssh-rsa (SHA-1, RFC 8332) is weak even when no ssh-dss is offered.
    r = _run(("curve25519-sha256",), ("ssh-rsa", "rsa-sha2-256", "ssh-ed25519"))
    assert r.summary.readiness is Readiness.CLASSICALLY_WEAK
    weak = next(f for f in r.findings if f.rule_id == "ssh.hostkey.weak")
    assert "ssh-rsa" in weak.title
    # rsa-sha2-256 (SHA-2) and ssh-ed25519 must NOT be dragged into the weak set.
    assert "rsa-sha2-256" not in weak.title
    assert "ssh-ed25519" not in weak.title


def test_weak_kex_group1_sha1_flagged() -> None:
    # A2/#143: widen weak detection to the KEX name-list the probe already collects.
    r = _run(("diffie-hellman-group1-sha1", "curve25519-sha256"), ("ssh-ed25519",))
    assert r.summary.readiness is Readiness.CLASSICALLY_WEAK
    weak = next(f for f in r.findings if f.rule_id == "ssh.kex.weak")
    assert "diffie-hellman-group1-sha1" in weak.title


def test_strong_kex_and_hostkeys_have_no_weak_findings() -> None:
    # A modern offer must not raise a false weak KEX/host-key finding.
    r = _run(("curve25519-sha256", "diffie-hellman-group14-sha256"), ("ssh-ed25519",))
    rules = {f.rule_id for f in r.findings}
    assert "ssh.kex.weak" not in rules
    assert "ssh.hostkey.weak" not in rules


def test_weak_transport_finding_is_emitted() -> None:
    result = _run(
        ("curve25519-sha256",),
        ("ssh-ed25519",),
        ciphers=("3des-cbc",),
        macs=("hmac-md5",),
    )
    finding = next(f for f in result.findings if f.rule_id == "ssh.transport.weak")
    assert "3des-cbc" in finding.title
    assert "hmac-md5" in finding.title


def test_none_cipher_is_emitted_in_cbom_with_weak_annotation() -> None:
    """Render SSH ``none`` as a zero-rated component with a weak annotation."""
    # Exercise scanner evidence through rendering so the fix cannot stop at a
    # helper-level classification and disappear from the customer CBOM.
    result = _run(
        ("curve25519-sha256",),
        ("ssh-ed25519",),
        ciphers=("none",),
    )

    payload = _cbom_components(result)
    component = payload["crypto/algorithm/none"]
    properties = component["cryptoProperties"]["algorithmProperties"]

    assert properties == {"classicalSecurityLevel": 0, "primitive": "other"}
    stream = io.StringIO()
    render_cbom(result, stream)
    assert any(
        annotation["bom-ref"] == "annotation/01-ssh.transport.weak"
        and "Weak SSH cipher or MAC offered (none)" in annotation["text"]
        for annotation in json.loads(stream.getvalue())["annotations"]
    )


def test_none_mac_is_emitted_in_cbom_with_weak_annotation() -> None:
    """Render SSH MAC ``none`` as a MAC component with a weak annotation."""
    result = _run(
        ("curve25519-sha256",),
        ("ssh-ed25519",),
        macs=("none",),
    )

    payload = _cbom_components(result)
    properties = payload["crypto/algorithm/none"]["cryptoProperties"]["algorithmProperties"]
    assert properties == {"primitive": "mac"}
    stream = io.StringIO()
    render_cbom(result, stream)
    assert any(
        annotation["bom-ref"] == "annotation/01-ssh.transport.weak"
        and "Weak SSH cipher or MAC offered (none)" in annotation["text"]
        for annotation in json.loads(stream.getvalue())["annotations"]
    )


def test_host_keys_emitted_as_cbom_components() -> None:
    # A5/#143: the CBOM previously dropped host keys; every offered host key must
    # now appear as a signature-classified crypto asset the endpoint provides.
    result = _run(("curve25519-sha256",), ("ssh-ed25519", "rsa-sha2-256"))
    stream = io.StringIO()
    render_cbom(result, stream)
    payload = json.loads(stream.getvalue())
    components = {item["bom-ref"]: item for item in payload["components"]}
    assert "crypto/algorithm/ssh-ed25519" in components
    assert "crypto/algorithm/rsa-sha2-256" in components
    # Classified honestly as classical signatures (no PQ resistance).
    props = components["crypto/algorithm/ssh-ed25519"]["cryptoProperties"]["algorithmProperties"]
    assert props["primitive"] == "signature"
    assert props["nistQuantumSecurityLevel"] == 0
    endpoint = next(d for d in payload["dependencies"] if d["ref"] == "endpoint")
    assert "crypto/algorithm/ssh-ed25519" in endpoint["provides"]
    assert "crypto/algorithm/rsa-sha2-256" in endpoint["provides"]


def test_weak_dss_hostkey_present_in_cbom_inventory() -> None:
    # A5/#143: the specific gap called out live — a weak ssh-dss host key was
    # observed yet absent from the CBOM. It must now be an inventory component.
    result = _run(("mlkem768x25519-sha256",), ("ssh-dss", "ssh-ed25519"))
    stream = io.StringIO()
    render_cbom(result, stream)
    payload = json.loads(stream.getvalue())
    refs = {item["bom-ref"] for item in payload["components"]}
    assert "crypto/algorithm/ssh-dss" in refs
    assert "crypto/algorithm/ssh-ed25519" in refs
    # The PQ hybrid KEX asset stays a KEM group, not a signature.
    assert "crypto/algorithm/mlkem768x25519-sha256" in refs


def _cbom_components(result) -> dict:
    stream = io.StringIO()
    render_cbom(result, stream)
    payload = json.loads(stream.getvalue())
    return {item["bom-ref"]: item for item in payload["components"]}


# --- #247: PQ-hybrid classifier must recognize non-x25519 families ---------------


@pytest.mark.parametrize(
    "kex_name",
    [
        "mlkem768nistp256-sha256",  # draft-kampanakis-curdle-ssh-pq-ke §2.3 (ML-KEM-768 + P-256)
        "mlkem1024nistp384-sha384",  # same draft (ML-KEM-1024 + P-384; CNSA 2.0)
        "x25519-kyber-512r3-sha256-d00@amazon.com",  # OQS-OpenSSH kex.h (AWS)
        "ecdh-nistp521-kyber-1024r3-sha512-d00@openquantumsafe.org",  # OQS-OpenSSH kex.h
        "sntrup761x25519-sha512",  # OpenSSH default (x25519 path, still must match)
    ],
)
def test_non_x25519_pq_hybrid_not_flagged_vulnerable(kex_name: str) -> None:
    # #247: these were all misread as quantum_vulnerable by the x25519-only allowlist.
    r = _run((kex_name, "ecdh-sha2-nistp256"), ("ssh-ed25519",))
    assert r.summary.readiness is Readiness.TRANSITIONAL_HYBRID
    assert any(f.rule_id == "ssh.kex.hybrid_offered" for f in r.findings)


def test_unknown_and_classical_kex_never_false_flagged() -> None:
    # #247 must not over-match: a novel vendor name and classical groups stay classical.
    r = _run(("some-future-kex@vendor", "curve25519-sha256"), ("ssh-ed25519",))
    assert r.summary.readiness is Readiness.QUANTUM_VULNERABLE


def test_empty_kex_offer_is_classical_only_no_crash() -> None:
    # Degenerate: a server offering no KEX name-list must not crash and stays classical.
    r = _run((), ("ssh-ed25519",))
    assert r.summary.readiness is Readiness.QUANTUM_VULNERABLE
    assert any(f.rule_id == "ssh.kex.classical_only" for f in r.findings)


def test_terrapin_posture_is_reported_as_fact_without_readiness_downgrade() -> None:
    result = _run(
        ("curve25519-sha256",),
        ("ssh-ed25519",),
        ciphers=("chacha20-poly1305@openssh.com", "aes256-ctr"),
        macs=("hmac-sha2-256-etm@openssh.com", "hmac-sha2-256"),
        strict_kex=True,
    )
    finding = next(f for f in result.findings if f.rule_id == "ssh.terrapin.posture")
    evidence = next(e for e in result.evidence if e.evidence_type == "ssh.terrapin")
    assert finding.severity.value == "info"
    assert finding.readiness is Readiness.NOT_APPLICABLE
    assert result.summary.readiness is Readiness.QUANTUM_VULNERABLE
    assert evidence.notes == (
        "strict KEX marker: present",
        "Terrapin-susceptible offered modes: chacha20-poly1305@openssh.com",
    )


def test_terrapin_fact_records_absent_strict_kex_and_no_relevant_modes() -> None:
    result = _run(
        ("curve25519-sha256",),
        ("ssh-ed25519",),
        ciphers=("aes256-ctr",),
        macs=("hmac-sha2-256",),
    )
    evidence = next(e for e in result.evidence if e.evidence_type == "ssh.terrapin")
    assert evidence.notes == (
        "strict KEX marker: absent",
        "Terrapin-susceptible offered modes: none",
    )


# --- #241: PQ-hybrid KEX component carries algorithmProperties + level -----------


def test_mlkem_hybrid_kex_component_has_nist_level_3() -> None:
    # #241: ML-KEM-768 hybrid must be a KEM primitive carrying its FIPS 203 category (3).
    components = _cbom_components(_run(("mlkem768x25519-sha256",), ("ssh-ed25519",)))
    props = components["crypto/algorithm/mlkem768x25519-sha256"]["cryptoProperties"][
        "algorithmProperties"
    ]
    assert props["primitive"] == "kem"
    assert props["nistQuantumSecurityLevel"] == 3
    assert props["parameterSetIdentifier"] == "ML-KEM-768"
    assert set(props["cryptoFunctions"]) == {"keygen", "encapsulate", "decapsulate"}


def test_sntrup_hybrid_kex_component_has_nist_level() -> None:
    # #241: sntrup761 hybrid must carry a non-zero, populated level (not omitted).
    components = _cbom_components(_run(("sntrup761x25519-sha512",), ("ssh-ed25519",)))
    props = components["crypto/algorithm/sntrup761x25519-sha512"]["cryptoProperties"][
        "algorithmProperties"
    ]
    assert props["primitive"] == "kem"
    assert props["nistQuantumSecurityLevel"] == 2


def test_nistp_mlkem_hybrid_component_level_5() -> None:
    # #241 + #247: a non-x25519 ML-KEM-1024 hybrid emits with its category (5).
    components = _cbom_components(_run(("mlkem1024nistp384-sha384",), ("ssh-ed25519",)))
    props = components["crypto/algorithm/mlkem1024nistp384-sha384"]["cryptoProperties"][
        "algorithmProperties"
    ]
    assert props["primitive"] == "kem"
    assert props["nistQuantumSecurityLevel"] == 5


# --- #242: full KEX inventory (classical + weak groups) as components ------------


def test_classical_only_endpoint_emits_all_kex_components() -> None:
    # #242: previously a classical-only endpoint emitted ZERO key-exchange components.
    components = _cbom_components(
        _run(
            ("curve25519-sha256", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256"),
            ("ssh-ed25519",),
        )
    )
    for ref in (
        "crypto/algorithm/curve25519-sha256",
        "crypto/algorithm/ecdh-sha2-nistp256",
        "crypto/algorithm/diffie-hellman-group14-sha256",
    ):
        assert ref in components, ref
        props = components[ref]["cryptoProperties"]["algorithmProperties"]
        assert props["primitive"] == "key-agree"
        assert props["nistQuantumSecurityLevel"] == 0


def test_hybrid_endpoint_keeps_classical_kex_groups() -> None:
    # #242: a hybrid endpoint previously dropped every classical KEX group it offered.
    components = _cbom_components(
        _run(("mlkem768x25519-sha256", "curve25519-sha256", "ecdh-sha2-nistp256"), ("ssh-ed25519",))
    )
    assert "crypto/algorithm/mlkem768x25519-sha256" in components
    assert "crypto/algorithm/curve25519-sha256" in components
    assert "crypto/algorithm/ecdh-sha2-nistp256" in components


def test_weak_kex_group_appears_as_component() -> None:
    # #242: weak KEX groups flagged by ssh.kex.weak must also appear in the inventory.
    components = _cbom_components(
        _run(("curve25519-sha256", "diffie-hellman-group1-sha1"), ("ssh-ed25519",))
    )
    assert "crypto/algorithm/diffie-hellman-group1-sha1" in components


def test_classify_kex_covers_families_and_unknown() -> None:
    # RSA key transport (RFC 4432) is PKE, level 0.
    rsa = classify.classify_kex("rsa2048-sha256")
    assert rsa is not None
    assert rsa.primitive == "pke"
    assert rsa.nist_quantum_security_level == 0
    # Finite-field DH is key-agreement with no named curve.
    dh = classify.classify_kex("diffie-hellman-group14-sha256")
    assert dh is not None
    assert dh.primitive == "key-agree"
    assert dh.curve is None
    # A PQ name whose specific parameter set is unrecognized: still KEM, level honestly None.
    novel = classify.classify_kex("mlkem999x25519-sha256")
    assert novel is not None
    assert novel.primitive == "kem"
    assert novel.nist_quantum_security_level is None
    # A fully unrecognized name is not classified (no fabricated primitive/level).
    assert classify.classify_kex("some-future-kex@vendor") is None


def test_unknown_kex_name_emitted_with_minimal_properties() -> None:
    # An unclassifiable KEX group is still inventoried, with no fabricated algorithmProperties.
    components = _cbom_components(_run(("some-future-kex@vendor",), ("ssh-ed25519",)))
    component = components["crypto/algorithm/some-future-kex@vendor"]
    assert "algorithmProperties" not in component["cryptoProperties"]


def test_ssh_rich_output_has_no_tls_cert_recommendation() -> None:
    """SSH scan must not emit the TLS cert-axis recommendation or probe rows."""
    r = _run(("mlkem768x25519-sha256",), ("ssh-ed25519",))
    buf = io.StringIO()
    render_rich(r, buf, verbosity=0)
    out = buf.getvalue()
    assert "certificate signature not yet inspected" not in out
    assert "cipher_suite" not in out
    assert "key_exchange" in out
    assert "host_keys" in out


def test_weak_ssh_kex_algorithm_is_visible_in_ciso_evaluation() -> None:
    result = _run(
        ("diffie-hellman-group1-sha1", "curve25519-sha256"),
        ("rsa-sha2-256",),
    )
    interpretation = result.summary.interpretation
    assert interpretation is not None
    evaluation = interpretation.display.evaluation
    assert interpretation.hygiene_status.value == "weak"
    assert evaluation.hardening == "Protocol hardening is required"
    assert "SSH weak algorithm offered: diffie-hellman-group1-sha1" in evaluation.observed_facts
