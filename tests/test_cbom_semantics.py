# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""CBOM semantic-guard, occurrence-provenance, and reproducibility tests.

Split out of tests/test_cbom.py (issue #298); the CycloneDX 1.7 structural
contract stays in the companion module. Shares fixtures via tests._cbom_fixtures.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from qureddy.core.certificate import CertificateObservation
from qureddy.core.errors import CbomError
from qureddy.core.models import Evidence, ObservationType
from qureddy.output.cbom_semantics import validate_cbom_semantics
from tests._cbom_fixtures import (
    _PROBE_ARGS,
    _build_result,
    _build_result_with_probe,
    _render,
    _render_reproducible_bytes,
)


class TestCbomSemanticGuard:
    """Pin BreachSAFE checks that structural validators do not all enforce."""

    @staticmethod
    def _base() -> dict:
        return _render(_build_result())

    def test_rejects_wrong_spec_version(self) -> None:
        payload = self._base()
        payload["specVersion"] = "1.6"

        with pytest.raises(CbomError, match=r"exactly 1\.7"):
            validate_cbom_semantics(payload)

    def test_rejects_dangling_reference(self) -> None:
        payload = self._base()
        endpoint = next(item for item in payload["dependencies"] if item["ref"] == "endpoint")
        endpoint["provides"].append("crypto/algorithm/missing")

        with pytest.raises(CbomError, match="dangling"):
            validate_cbom_semantics(payload)

    def test_rejects_dangling_cipher_suite_algorithm_ref(self) -> None:
        # #144: the runtime validator must catch a dangling cipher-suite algorithm ref,
        # not only the CI harness.
        payload = self._base()
        protocol = next(
            component
            for component in payload["components"]
            if component.get("cryptoProperties", {}).get("protocolProperties")
        )
        protocol["cryptoProperties"]["protocolProperties"]["cipherSuites"][0]["algorithms"].append(
            "crypto/algorithm/missing"
        )

        with pytest.raises(CbomError, match="dangling"):
            validate_cbom_semantics(payload)

    def test_rejects_duplicate_reference(self) -> None:
        payload = self._base()
        payload["components"].append(dict(payload["components"][0]))

        with pytest.raises(CbomError, match="duplicate"):
            validate_cbom_semantics(payload)

    def test_rejects_duplicate_tool_reference(self) -> None:
        payload = self._base()
        duplicate = dict(payload["metadata"]["tools"]["components"][0])
        duplicate["bom-ref"] = "endpoint"
        payload["metadata"]["tools"]["components"].append(duplicate)

        with pytest.raises(CbomError, match="duplicate"):
            validate_cbom_semantics(payload)

    def test_rejects_unresolved_auto_generated_reference(self) -> None:
        payload = self._base()
        payload["components"].append({"bom-ref": "BomRef.1.2"})

        with pytest.raises(CbomError, match="auto-generated"):
            validate_cbom_semantics(payload)

    @pytest.mark.parametrize(
        ("name", "value"),
        [
            ("note", "-----BEGIN DSA PRIVATE KEY-----"),
            ("note", "-----BEGIN OPENSSH PRIVATE KEY-----"),
            ("access_token", "not-a-real-token-but-still-secret"),
            ("credential", "username:password"),
            ("session_key", "session-secret-value"),
        ],
    )
    def test_rejects_secret_like_material(self, name: str, value: str) -> None:
        payload = self._base()
        payload["metadata"]["properties"].append(
            {
                "name": name,
                "value": value,
            }
        )

        with pytest.raises(CbomError, match="secret-like"):
            validate_cbom_semantics(payload)


def _command_hash_property(payload: dict) -> str:
    """Extract the probe command digest from a component's evidence occurrences (#287).

    The command hash rides in the occurrence ``additionalContext`` (``command_sha256=<hex>``)
    now that evidence is attached to the asset it describes, not a flat metadata block.
    """
    components = [payload["metadata"].get("component", {}), *payload.get("components", [])]
    for component in components:
        for occurrence in component.get("evidence", {}).get("occurrences", []):
            match = re.search(
                r"command_sha256=([0-9a-f]{64})", occurrence.get("additionalContext", "")
            )
            if match:
                return match.group(1)
    msg = "no command_sha256 in any component's evidence occurrences"
    raise AssertionError(msg)


def _parse_occurrence_context(context: str) -> dict[str, str]:
    """Parse an occurrence ``additionalContext`` under the #307 key=value grammar.

    Grammar (documented in docs/reference/cbom-occurrence-provenance.md): ``key=value``
    pairs joined by ``"; "``; keys are lower_snake_case; a value never contains ``"; "``
    or ``"="``, so split-on-``"; "`` then partition-on-first-``"="`` is a total parse.
    """
    fields: dict[str, str] = {}
    for token in context.split("; "):
        key, sep, value = token.partition("=")
        assert sep == "=", f"occurrence context token is not key=value: {token!r}"
        assert re.fullmatch(r"[a-z][a-z0-9_]*", key), f"non-grammar key: {key!r}"
        fields[key] = value
    return fields


def _all_occurrences(payload: dict) -> list[dict]:
    components = [payload["metadata"].get("component", {}), *payload.get("components", [])]
    return [
        occurrence
        for component in components
        for occurrence in component.get("evidence", {}).get("occurrences", [])
    ]


class TestOccurrenceProvenanceGrammar:
    """Occurrence provenance is a queryable key=value grammar, not free-text prose (#307)."""

    def test_every_occurrence_context_is_strict_kv(self) -> None:
        occurrences = _all_occurrences(_render(_build_result_with_probe("/usr/bin/openssl")))
        assert occurrences, "expected at least one evidence occurrence"
        for occurrence in occurrences:
            fields = _parse_occurrence_context(occurrence["additionalContext"])
            assert "observation" in fields, fields
            assert "evidence_type" in fields, fields

    def test_probe_fields_are_individually_queryable(self) -> None:
        occurrences = _all_occurrences(_render(_build_result_with_probe("/usr/bin/openssl")))
        probe = next(o for o in occurrences if "command_sha256=" in o["additionalContext"])
        fields = _parse_occurrence_context(probe["additionalContext"])
        assert fields["observation"] == "negotiated"
        assert fields["evidence_type"] == "tls.negotiation"
        assert fields["return_code"] == "0"
        assert len(fields["command_sha256"]) == 64

    def test_confidence_field_on_every_occurrence(self) -> None:
        # #326: confidence is preserved as a queryable field on every occurrence.
        for occurrence in _all_occurrences(_render(_build_result_with_probe("/usr/bin/openssl"))):
            assert "confidence" in _parse_occurrence_context(occurrence["additionalContext"])

    def test_occurrence_separates_target_location_from_scanner_source(self) -> None:
        occurrences = _all_occurrences(_render(_build_result()))
        assert occurrences, "expected at least one evidence occurrence"
        for occurrence in occurrences:
            assert occurrence["location"] == "tls://example.com:443"
            fields = _parse_occurrence_context(occurrence["additionalContext"])
            assert fields["source"] == "qureddy.scanners.tls.parse"

    def test_identical_occurrences_are_deduplicated(self) -> None:
        base = _build_result()
        evidence = base.evidence[0]
        payload = _render(base.model_copy(update={"evidence": (evidence, evidence)}))
        occurrences = next(
            component["evidence"]["occurrences"]
            for component in payload["components"]
            if component["bom-ref"] == "crypto/algorithm/x25519mlkem768"
        )
        assert len(occurrences) == 1

    def test_certificate_evidence_reaches_certificate_and_related_algorithms(self) -> None:
        base = _build_result()
        certificate = CertificateObservation(
            subject="CN=example.com",
            issuer="CN=issuer",
            not_before="Jul  3 00:00:00 2026 GMT",
            not_after="Sep 30 23:59:59 2026 GMT",
            serial="ABC",
            signature_algorithm="ecdsa-with-SHA256",
            public_key_summary="Public Key Algorithm: id-ecPublicKey",
            is_self_signed=False,
            is_post_quantum_signature=False,
            public_key_algorithm="id-ecPublicKey",
            public_key_bits=256,
        )
        evidence = Evidence(
            id="ev-cert",
            asset_id="asset-1",
            evidence_type="tls.cert.signature",
            observation_type=ObservationType.OBSERVED,
            source="qureddy.scanners.tls.cert_sig",
            certificate_record=certificate,
        )
        payload = _render(base.model_copy(update={"evidence": (evidence,)}))
        components = {item["bom-ref"]: item for item in payload["components"]}
        for ref in (
            "crypto/certificate/leaf",
            "crypto/algorithm/ec-256",
            "crypto/algorithm/ecdsa-with-sha256",
        ):
            assert components[ref]["evidence"]["occurrences"]

    def test_subjectless_evidence_attaches_to_endpoint(self) -> None:
        # #326: evidence with no crypto subject (a bare cert/failure record) is no longer
        # dropped — it becomes an occurrence on the endpoint, so every evidence item maps.
        base = _build_result()
        subjectless = Evidence(
            id="ev-cert",
            asset_id=base.assets[0].id,
            evidence_type="tls.cert.signature",
            observation_type=ObservationType.NOT_TESTABLE,
            source="qureddy.scanners.tls.cert_sig",
        )
        result = base.model_copy(update={"evidence": (*base.evidence, subjectless)})
        payload = _render(result)
        endpoint_occ = payload["metadata"]["component"].get("evidence", {}).get("occurrences", [])
        assert any(
            "evidence_type=tls.cert.signature" in o["additionalContext"] for o in endpoint_occ
        )


class TestReproducibleHostPathCanonicalization:
    """Reproducible CBOM must not encode host-specific probe executable paths (#207)."""

    _HOST_A = "/opt/homebrew/opt/openssl@3.5/bin/openssl"
    _HOST_B = "/usr/bin/openssl"

    def test_reproducible_cbom_is_byte_identical_across_host_openssl_paths(self) -> None:
        # #207: two hosts observing identical crypto, differing only in where their
        # openssl binary lives, must produce byte-identical reproducible CBOM.
        host_a = _render_reproducible_bytes(_build_result_with_probe(self._HOST_A))
        host_b = _render_reproducible_bytes(_build_result_with_probe(self._HOST_B))
        assert host_a == host_b

    def test_reproducible_command_hash_is_over_basename_not_absolute_path(self) -> None:
        # The hashed command must attribute the openssl subcommand (basename + args)
        # without binding to the host install location.
        payload = json.loads(_render_reproducible_bytes(_build_result_with_probe(self._HOST_A)))
        expected = hashlib.sha256(
            " ".join(["openssl", *_PROBE_ARGS]).encode(),
        ).hexdigest()
        assert _command_hash_property(payload) == expected

    def test_non_reproducible_output_retains_host_specific_path(self) -> None:
        # Guardrail: operator diagnostics still get the exact local path, so the two
        # hosts' non-reproducible command hashes DO differ. This also proves the fix
        # is scoped to reproducible mode (and that the path genuinely leaked before).
        payload_a = _render(_build_result_with_probe(self._HOST_A))
        payload_b = _render(_build_result_with_probe(self._HOST_B))
        assert _command_hash_property(payload_a) != _command_hash_property(payload_b)
        expected_a = hashlib.sha256(
            " ".join([self._HOST_A, *_PROBE_ARGS]).encode(),
        ).hexdigest()
        assert _command_hash_property(payload_a) == expected_a

    def test_reproducible_cbom_is_byte_identical_across_pythonhashseed(self) -> None:
        # #196: prove set/dict iteration order cannot alter emitted bytes across
        # processes by regenerating the same reproducible scan under two distinct
        # PYTHONHASHSEED values and comparing the final byte streams exactly.
        repo_root = Path(__file__).resolve().parents[1]
        child = (
            "import sys; from tests._cbom_fixtures import _emit_reproducible_cbom_bytes; "
            "sys.stdout.write(_emit_reproducible_cbom_bytes())"
        )
        outputs: list[str] = []
        for seed in ("1", "2"):
            env = {**os.environ, "PYTHONHASHSEED": seed}
            completed = subprocess.run(  # noqa: S603 - fixed interpreter + literal script.
                [sys.executable, "-c", child],
                check=True,
                capture_output=True,
                text=True,
                cwd=repo_root,
                env=env,
            )
            outputs.append(completed.stdout)
        assert outputs[0] == outputs[1]
        # sanity: the compared bytes are a real CBOM, not empty/error output.
        assert json.loads(outputs[0])["bomFormat"] == "CycloneDX"
