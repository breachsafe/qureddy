# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Conformance matrix for pinned CycloneDX fixture bytes."""

from __future__ import annotations

import json

import pytest

from qureddy.core.certificate import CertificateObservation
from qureddy.core.models import Evidence, ObservationType, ScanTarget
from tests._cbom_fixtures import _build_result, _render
from tests.conformance.harness import (
    FIXTURE_DIR,
    load_manifest,
    official_errors,
    semantic_errors,
    sha256,
    verify_schema_assets,
)


def _cases(kind: str) -> list[pytest.param]:
    fixtures = load_manifest()["fixtures"]
    return [
        pytest.param(name, details, id=name)
        for name, details in fixtures.items()
        if details["kind"] == kind
    ]


def _load(name: str, details: dict[str, object]) -> dict[str, object]:
    path = FIXTURE_DIR / str(details["kind"]) / f"{name}.cbom.json"
    assert sha256(path) == details["sha256"]
    return json.loads(path.read_text(encoding="utf-8"))


def _sidecar(name: str, details: dict[str, object]) -> dict[str, str]:
    path = FIXTURE_DIR / str(details["kind"]) / f"{name}.provenance.txt"
    entries = (
        line.split(":", maxsplit=1)
        for line in path.read_text(encoding="utf-8").splitlines()
        if ":" in line
    )
    return {key.strip(): value.strip() for key, value in entries}


def test_vendored_schema_hashes_match_pinned_manifest() -> None:
    verify_schema_assets()


@pytest.mark.parametrize(("name", "details"), _cases("positive"))
def test_positive_fixture_passes_official_and_semantic_gates(
    name: str, details: dict[str, object]
) -> None:
    payload = _load(name, details)

    assert not official_errors(payload)
    assert not semantic_errors(payload)


@pytest.mark.parametrize(("name", "details"), _cases("negative"))
def test_negative_fixture_detection_matrix(name: str, details: dict[str, object]) -> None:
    payload = _load(name, details)

    assert bool(official_errors(payload)) is details["official_rejects"]
    assert bool(semantic_errors(payload)) is details["semantic_rejects"]


@pytest.mark.parametrize(("name", "details"), _cases("positive") + _cases("negative"))
def test_fixture_has_exact_provenance(name: str, details: dict[str, object]) -> None:
    sidecar = _sidecar(name, details)

    assert sidecar["fixture"] == name
    assert sidecar["classification"] == details["classification"]
    assert sidecar["sha256"] == details["sha256"]
    if details["kind"] == "positive":
        producer = load_manifest()["producer"]
        assert sidecar["producer_commit"] == producer["commit"]
        assert sidecar["installed_wheel_sha256"] == producer["installed_wheel_sha256"]
        assert sidecar["captured_utc"].endswith("Z")
        assert "command" in sidecar
        assert "exit_code" in sidecar
    else:
        positive = load_manifest()["fixtures"]["p2-classical-tls"]
        assert sidecar["not_network_evidence"] == "true"
        assert sidecar["base_sha256"] == positive["sha256"]
        assert sidecar["derived_from"] == "fixtures/positive/p2-classical-tls.cbom.json"
        assert sidecar["mutation"]


def test_positive_fixture_inventory_matrix() -> None:
    fixtures = {
        name: _load(name, details)
        for name, details in load_manifest()["fixtures"].items()
        if details["kind"] == "positive"
    }
    component_refs = {
        name: {component["bom-ref"] for component in payload.get("components", [])}
        for name, payload in fixtures.items()
    }

    assert "crypto/algorithm/x25519mlkem768" in component_refs["p1-hybrid-tls"]
    assert "crypto/algorithm/x25519mlkem768" not in component_refs["p2-classical-tls"]
    assert "crypto/protocol/ssh-2.0" in component_refs["p3-ssh-hybrid"]
    assert not component_refs["p4-sparse-unknown"]
    assert not component_refs["p5-failed-target"]
    assert not component_refs["p6-missing-openssl"]
    assert "crypto/certificate/leaf" in component_refs["p7-leaf-cert"]
    certificate = next(
        component
        for component in fixtures["p7-leaf-cert"]["components"]
        if component["bom-ref"] == "crypto/certificate/leaf"
    )
    assert certificate["cryptoProperties"]["certificateProperties"]["serialNumber"]
    for payload in fixtures.values():
        for component in payload.get("components", []):
            if component.get("cryptoProperties", {}).get("assetType") == "certificate":
                properties = {
                    prop["name"]: prop["value"] for prop in component.get("properties", [])
                }
                assert properties["qureddy:certificate.is_self_signed"] in {
                    "true",
                    "false",
                    "unknown",
                }


def test_certificate_fixture_matches_current_emitter() -> None:
    """Keep the captured certificate corpus coupled to the CBOM emitter.

    Schema validation cannot see an emitter/fixture mismatch when both the old
    and new shapes are schema-valid.  Re-render the deterministic certificate
    facts captured by p7 and compare the complete certificate component so a
    future CBOM shape change fails closed until its fixture is deliberately
    refreshed.
    """
    fixtures = load_manifest()["fixtures"]
    captured = _load("p7-leaf-cert", fixtures["p7-leaf-cert"])
    captured_certificate = next(
        component
        for component in captured["components"]
        if component["bom-ref"] == "crypto/certificate/leaf"
    )
    certificate = CertificateObservation(
        subject="CN=github.com",
        issuer=("C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV E36"),
        not_before="Jul  3 00:00:00 2026 GMT",
        not_after="Sep 30 23:59:59 2026 GMT",
        serial="72010E03F4A067FE4E796266430718F6",
        signature_algorithm="ecdsa-with-SHA256",
        public_key_summary="Public Key Algorithm: id-ecPublicKey",
        is_self_signed=False,
        is_post_quantum_signature=False,
        public_key_algorithm="id-ecPublicKey",
        public_key_bits=256,
    )
    result = _build_result()
    result = result.model_copy(
        update={
            "target": ScanTarget(
                original_input="github.com",
                host="github.com",
                port=443,
                sni="github.com",
                locator="tls://github.com:443",
            )
        }
    )
    evidence = Evidence(
        id="ev-cert",
        asset_id="asset-1",
        evidence_type="tls.cert.signature",
        observation_type=ObservationType.OBSERVED,
        source="qureddy.scanners.tls.cert_sig",
        certificate_record=certificate,
    )
    rendered = _render(result.model_copy(update={"evidence": (*result.evidence, evidence)}))
    emitted_certificate = next(
        component
        for component in rendered["components"]
        if component["bom-ref"] == "crypto/certificate/leaf"
    )

    assert emitted_certificate == captured_certificate
