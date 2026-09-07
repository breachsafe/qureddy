# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Evidence-record builders for the TLS scanner.

Pure functions that turn a `ProbeResult` into the locked `Evidence`
shape downstream consumers (policy, summary, JSON output) expect.
Extracted from `scanner.py` to keep that file under the 400-line
hard ceiling.

Evidence projection:

    ``ProbeResult.parser_input``
    └── ``parse_brief_output``
        ├── protocol version + cipher suite → negotiation evidence
        ├── key-exchange group → algorithm profile fields
        └── parser or probe failure → explicit failure evidence

The CBOM renderer consumes the resulting ``Evidence`` record. This module
does not reconstruct negotiated values from probe arguments or excerpts.
"""

from __future__ import annotations

from typing import TypedDict

from qureddy.core.algorithm_profile import classify_key_exchange
from qureddy.core.ids import new_id
from qureddy.core.models import (
    Asset,
    Evidence,
    FailureCategory,
    ObservationType,
    ProbeResult,
    ProbeRole,
    ScanTarget,
)
from qureddy.scanners.common.assets import build_endpoint_asset
from qureddy.scanners.tls.parse import ParsedNegotiation, parse_brief_output


class _AlgorithmFields(TypedDict):
    algorithm: str | None
    primitive: str | None
    parameter_set_identifier: str | None
    nist_quantum_security_level: int | None


def _algorithm_fields(name: str | None) -> _AlgorithmFields:
    """Return canonical model fields for one negotiated key-exchange name."""
    profile = classify_key_exchange(name) if name is not None else None
    return {
        "algorithm": name,
        "primitive": profile.primitive if profile is not None else None,
        "parameter_set_identifier": (
            profile.parameter_set_identifier if profile is not None else None
        ),
        "nist_quantum_security_level": (
            profile.nist_quantum_security_level if profile is not None else None
        ),
    }


def build_asset(target: ScanTarget) -> Asset:
    """Construct the single `Asset` record for one TLS endpoint scan."""
    return build_endpoint_asset(target, asset_type="tls.endpoint")


def evidence_from_probe(
    *,
    asset: Asset,
    probe: ProbeResult,
    expected_group: str,
    probe_role: ProbeRole,
) -> Evidence:
    """Turn a `ProbeResult` into the appropriate `Evidence` record.

    Three branches, mutually exclusive: probe failed, probe succeeded
    but parser couldn't classify, or probe succeeded and parser found
    a clean negotiation. Each branch builds an `Evidence` with the
    field set that matches the verdict shape.

    Issue #232: `probe_role` records whether this evidence is testing
    hybrid PQ readiness or is a classical-fallback diagnostic control —
    a failure in the latter role is not evidence the former failed, and
    `core/policy.py` needs this to attribute failures correctly.
    """
    if probe.failure_category is not None or probe.return_code != 0:
        return _evidence_for_probe_failure(asset, probe, expected_group, probe_role)
    parsed = parse_brief_output(
        probe.parser_input or probe.stdout_excerpt, expected_group=expected_group
    )
    if parsed.failure_category is not None:
        return _evidence_for_parse_failure(asset, probe, parsed, expected_group, probe_role)
    return _evidence_for_negotiation(asset, probe, parsed, expected_group, probe_role)


def _evidence_for_probe_failure(
    asset: Asset,
    probe: ProbeResult,
    expected_group: str,
    probe_role: ProbeRole,
) -> Evidence:
    # Trust the probe module's stderr-based classification verbatim.
    # Falling back to TLS_HANDSHAKE_FAILED here would erase
    # target_connect_failed / sni_required_or_wrong /
    # middlebox_or_mtu_failure — the categories retry policy needs.
    category = probe.failure_category or FailureCategory.TLS_HANDSHAKE_FAILED
    return Evidence(
        id=new_id("ev"),
        asset_id=asset.id,
        evidence_type="tls.probe.failure",
        observation_type=ObservationType.OBSERVED,
        source="qureddy.openssl_probe",
        probe_role=probe_role,
        expected_group=expected_group,
        probe_result=probe,
        failure_category=category,
        notes=(f"probe for {expected_group} failed", probe.stderr_excerpt[:200]),
    )


def _evidence_for_parse_failure(
    asset: Asset,
    probe: ProbeResult,
    parsed: ParsedNegotiation,
    expected_group: str,
    probe_role: ProbeRole,
) -> Evidence:
    return Evidence(
        id=new_id("ev"),
        asset_id=asset.id,
        evidence_type="tls.probe.parse",
        observation_type=ObservationType.OBSERVED,
        source="qureddy.scanners.tls.parse",
        protocol_version=parsed.protocol_version,
        cipher_suite=parsed.cipher_suite,
        **_algorithm_fields(parsed.negotiated_group),
        negotiated_group=parsed.negotiated_group,
        handshake_signature=parsed.handshake_signature,
        handshake_hash=parsed.handshake_hash,
        key_bits=parsed.key_bits,
        probe_role=probe_role,
        expected_group=expected_group,
        probe_result=probe,
        failure_category=parsed.failure_category,
        notes=parsed.notes,
    )


def _evidence_for_negotiation(
    asset: Asset,
    probe: ProbeResult,
    parsed: ParsedNegotiation,
    expected_group: str,
    probe_role: ProbeRole,
) -> Evidence:
    return Evidence(
        id=new_id("ev"),
        asset_id=asset.id,
        evidence_type="tls.negotiation",
        observation_type=ObservationType.NEGOTIATED,
        source="qureddy.scanners.tls.parse",
        protocol_version=parsed.protocol_version,
        cipher_suite=parsed.cipher_suite,
        **_algorithm_fields(parsed.negotiated_group),
        negotiated_group=parsed.negotiated_group,
        handshake_signature=parsed.handshake_signature,
        handshake_hash=parsed.handshake_hash,
        key_bits=parsed.key_bits,
        probe_role=probe_role,
        expected_group=expected_group,
        probe_result=probe,
        notes=parsed.notes,
    )
