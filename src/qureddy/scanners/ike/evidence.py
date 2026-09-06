# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Project parsed IKE responses onto the canonical evidence contract."""

from __future__ import annotations

from typing import TYPE_CHECKING

from qureddy.core.ids import new_id
from qureddy.core.models import Confidence, Evidence, ObservationType, ProbeResult
from qureddy.scanners.ike.types import IKEParseStatus

if TYPE_CHECKING:
    from qureddy.scanners.ike.parser import ParsedIKEResponse


def _mode_evidence(
    response: ParsedIKEResponse,
    *,
    asset_id: str,
    source: str,
    probe_result: ProbeResult,
    nat_t: bool,
) -> Evidence:
    """Build the one mode-level record for a parsed responder state."""
    if probe_result.failure_category is not None:
        observation = ObservationType.NOT_TESTABLE
    elif response.status is IKEParseStatus.NO_RESPONSE:
        observation = ObservationType.NO_RESPONSE
    else:
        observation = ObservationType.OBSERVED
    return Evidence(
        id=new_id("ev"),
        asset_id=asset_id,
        evidence_type=f"ike.mode.{response.status.value}",
        observation_type=observation,
        source=source,
        protocol="ike",
        protocol_version=response.protocol_version,
        confidence=Confidence.LOW,
        probe_result=probe_result,
        failure_category=probe_result.failure_category,
        notes=(
            f"exchange_mode={response.mode.value}",
            f"transport={'nat_t' if nat_t else 'udp'}",
        ),
    )


def _algorithm_evidence(
    response: ParsedIKEResponse, *, asset_id: str, source: str, nat_t: bool
) -> list[Evidence]:
    """Build lossless, low-confidence records for tool-reported transforms."""
    items = (
        *(("ike.cipher", None, name) for name in response.encryption),
        *(("ike.prf", None, name) for name in response.prf),
        *(("ike.integrity", None, name) for name in response.integrity),
        *(("ike.dh_group", number, name) for number, name in response.dh_groups),
    )
    return [
        Evidence(
            id=new_id("ev"),
            asset_id=asset_id,
            evidence_type=evidence_type,
            observation_type=ObservationType.OBSERVED,
            source=source,
            protocol="ike",
            protocol_version=response.protocol_version,
            algorithm=name,
            confidence=Confidence.LOW,
            ike_group_id=group_id,
            notes=(
                "tool-reported transform identifier",
                f"exchange_mode={response.mode.value}",
                f"transport={'nat_t' if nat_t else 'udp'}",
            ),
        )
        for evidence_type, group_id, name in items
    ]


def _notify_evidence(
    response: ParsedIKEResponse, *, asset_id: str, source: str, nat_t: bool
) -> Evidence:
    """Build an explicit rejection record whose name survives serialization."""
    return Evidence(
        id=new_id("ev"),
        asset_id=asset_id,
        evidence_type="ike.notify",
        observation_type=ObservationType.OBSERVED,
        source=source,
        protocol="ike",
        protocol_version=response.protocol_version,
        algorithm=response.responder_notify,
        confidence=Confidence.LOW,
        notes=(
            f"exchange_mode={response.mode.value}",
            f"transport={'nat_t' if nat_t else 'udp'}",
        ),
    )


def _exposure_evidence(
    response: ParsedIKEResponse,
    *,
    asset_id: str,
    source: str,
    nat_t: bool,
    psk_hash_exposed: bool,
) -> list[Evidence]:
    """Emit exposure facts without retaining identity or HASH_R material."""
    transport = f"transport={'nat_t' if nat_t else 'udp'}"
    mode = f"exchange_mode={response.mode.value}"
    records: list[Evidence] = []
    if response.identity_exposed:
        records.append(
            Evidence(
                id=new_id("ev"),
                asset_id=asset_id,
                evidence_type="ike.identity_exposed",
                observation_type=ObservationType.OBSERVED,
                source=source,
                protocol="ike",
                protocol_version="IKEv1",
                confidence=Confidence.LOW,
                notes=(
                    "key exchange, nonce, and identity payloads observed before authentication",
                    mode,
                    transport,
                ),
            )
        )
    if psk_hash_exposed:
        records.append(
            Evidence(
                id=new_id("ev"),
                asset_id=asset_id,
                evidence_type="ike.psk_hash_exposed",
                observation_type=ObservationType.OBSERVED,
                source=source,
                protocol="ike",
                protocol_version="IKEv1",
                confidence=Confidence.LOW,
                notes=(
                    "offline PSK-cracking parameters observed; values omitted",
                    mode,
                    transport,
                ),
            )
        )
    return records


def response_evidence(
    response: ParsedIKEResponse,
    *,
    asset_id: str,
    source: str,
    probe_result: ProbeResult,
    nat_t: bool,
    psk_hash_exposed: bool = False,
) -> list[Evidence]:
    """Project one parsed response onto the canonical Evidence model."""
    records = [
        _mode_evidence(
            response,
            asset_id=asset_id,
            source=source,
            probe_result=probe_result,
            nat_t=nat_t,
        )
    ]
    if response.status is IKEParseStatus.REJECTED and response.responder_notify:
        records.append(_notify_evidence(response, asset_id=asset_id, source=source, nat_t=nat_t))
    if response.status is not IKEParseStatus.RESPONDED:
        return records
    records.extend(_algorithm_evidence(response, asset_id=asset_id, source=source, nat_t=nat_t))
    records.extend(
        _exposure_evidence(
            response,
            asset_id=asset_id,
            source=source,
            nat_t=nat_t,
            psk_hash_exposed=psk_hash_exposed,
        )
    )
    return records
