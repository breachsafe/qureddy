# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""IKE-specific CBOM provenance and protocol-version tests."""

from __future__ import annotations

from cyclonedx.model.bom import Bom

from qureddy.core.models import ExternalToolDependency, ObservationType
from qureddy.output.cbom import _add_tool_provenance
from qureddy.output.cbom_cipher import cipher_algorithm_properties
from qureddy.output.cbom_components import _bare_protocol_version
from qureddy.output.cbom_metadata import tool_dependency_properties
from tests._cbom_fixtures import _build_result, _render


def test_ike_protocol_version_uses_cyclonedx_major_minor_form() -> None:
    assert _bare_protocol_version("ike", "IKEv2") == "2.0"


def test_ike_cipher_projection_preserves_null_and_3des_classification() -> None:
    """Preserve explicit zero and 3DES strength in the IKE projection."""
    # IKE uses the shared cipher classifier, so these vectors guard cross-
    # protocol behavior rather than only the TLS legacy emitter.
    null = cipher_algorithm_properties("ENCR_NULL")
    triple_des = cipher_algorithm_properties("ENCR_3DES")

    assert null.primitive is not None
    assert null.primitive.value == "other"
    assert null.classical_security_level == 0
    assert triple_des.primitive is not None
    assert triple_des.primitive.value == "block-cipher"
    assert triple_des.classical_security_level == 112


def test_ike_ciphers_are_emitted_in_rendered_cbom() -> None:
    """Keep IKE cipher classifications intact through CBOM rendering."""
    # Verify the values survive the complete evidence-to-CBOM projection.
    result = _build_result()
    evidence = tuple(
        result.evidence[0].model_copy(
            update={
                "id": f"ike-{name}",
                "evidence_type": "ike.cipher",
                "observation_type": ObservationType.OFFERED,
                "algorithm": name,
                "cipher_suite": None,
                "negotiated_group": None,
            }
        )
        for name in ("ENCR_NULL", "ENCR_3DES")
    )

    payload = _render(result.model_copy(update={"evidence": evidence}))
    components = {item["name"]: item for item in payload["components"]}

    assert components["ENCR_NULL"]["cryptoProperties"]["algorithmProperties"] == {
        "classicalSecurityLevel": 0,
        "primitive": "other",
    }
    assert components["ENCR_3DES"]["cryptoProperties"]["algorithmProperties"] == {
        "classicalSecurityLevel": 112,
        "primitive": "block-cipher",
    }


def test_external_tool_provenance_preserves_path_only_when_nondeterministic() -> None:
    dependency = ExternalToolDependency(name="ike-scan", path="/usr/bin/ike-scan", version="1.9.5")
    result = _build_result().model_copy(update={"dependencies": (dependency,)})
    bom = Bom()

    _add_tool_provenance(bom, result)

    tool = next(item for item in bom.metadata.tools.components if item.name == "ike-scan")
    properties = {item.name: item.value for item in tool.properties}
    assert properties["qureddy:collector.role"] == "external-tool-adapter"
    assert properties["qureddy:collector.path"] == "/usr/bin/ike-scan"
    deterministic = tool_dependency_properties(dependency, reproducible=True)
    assert [item.name for item in deterministic] == ["qureddy:collector.role"]
