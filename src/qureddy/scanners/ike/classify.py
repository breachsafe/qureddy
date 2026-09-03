# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Pure IKE policy classification over normalized lower-trust evidence."""

from __future__ import annotations

from collections.abc import Iterable
from types import MappingProxyType

from qureddy.core.ids import new_id
from qureddy.core.models import Asset, Confidence, Evidence, Finding, Readiness, Severity

_PROHIBITED_ALGORITHMS = frozenset(
    {
        "DES",
        "ENCR_DES",
        "MD5",
        "NULL",
        "ENCR_NULL",
        "HMAC_MD5",
        "HMAC_MD5_96",
        "PRF_HMAC_MD5",
        "AUTH_HMAC_MD5_96",
        "AUTH_DES_MAC",
        "AUTH_KPDK_MD5",
    }
)
_LEGACY_ALGORITHMS = frozenset({"3DES", "ENCR_3DES"})
_PROHIBITED_DH_GROUPS = frozenset({1, 22})
_DISCOURAGED_DH_GROUPS = frozenset({2, 5, 23, 24})
# Current named classical IKEv2 groups in the pinned IANA registry. Reserved and
# unassigned identifiers are excluded; the separately scheduled registry will own
# this vocabulary when it lands.
_CLASSICAL_DH_GROUPS = frozenset({1, 2, 5, *range(14, 35)})
_ML_KEM_GROUPS = MappingProxyType({35: "ML-KEM-512", 36: "ML-KEM-768", 37: "ML-KEM-1024"})


def _finding(
    asset: Asset,
    evidence: Iterable[Evidence],
    *,
    rule_id: str,
    finding_type: str,
    title: str,
    description: str,
    severity: Severity,
    readiness: Readiness,
) -> Finding:
    """Build one finding that can only cite supplied evidence records."""
    records = tuple(evidence)
    if not records:
        raise ValueError(f"{rule_id} requires evidence")
    return Finding(
        id=new_id("finding"),
        asset_id=asset.id,
        evidence_ids=tuple(record.id for record in records),
        rule_id=rule_id,
        finding_type=finding_type,
        title=title,
        description=description,
        severity=severity,
        readiness=readiness,
        confidence=Confidence.LOW,
        protocol="ike",
    )


def _responding_modes(evidence: list[Evidence]) -> list[Evidence]:
    """Return clean mode-level observations that prove responder presence."""
    return [
        record
        for record in evidence
        if record.evidence_type == "ike.mode.responded"
        and record.observation_type.value == "observed"
        and record.failure_category is None
    ]


def _algorithm_name(record: Evidence) -> str:
    """Normalize cipher key lengths while preserving integrity name suffixes."""
    name = record.algorithm or ""
    if record.evidence_type != "ike.cipher":
        return name
    stem, separator, suffix = name.rpartition("_")
    return stem if separator and suffix.isdigit() else name


def _protocol_findings(asset: Asset, evidence: list[Evidence]) -> list[Finding]:
    """Build protocol-version findings from observed responder modes."""
    modes = _responding_modes(evidence)
    ikev1 = [record for record in modes if record.protocol_version == "IKEv1"]
    ikev2 = [record for record in modes if record.protocol_version == "IKEv2"]
    findings: list[Finding] = []
    if ikev1:
        findings.append(
            _finding(
                asset,
                ikev1,
                rule_id="ike.v1.present",
                finding_type="ike.protocol.historic",
                title="IKEv1 responder detected",
                description=(
                    "The external probe received an IKEv1 response. RFC 9395 moved IKEv1 "
                    "to Historic status and calls for migration to IKEv2."
                ),
                severity=Severity.HIGH,
                readiness=Readiness.CLASSICALLY_WEAK,
            )
        )
    if ikev2 and not ikev1:
        findings.append(
            _finding(
                asset,
                ikev2,
                rule_id="ike.v2.tool_reported",
                finding_type="ike.responder.tool_reported",
                title="IKEv2 responder detected by ike-scan",
                description=(
                    "Stock ike-scan reported an IKEv2 response. Its IKEv2 sender is experimental "
                    "and sends only its default proposal, so this finding makes no readiness claim."
                ),
                severity=Severity.INFO,
                readiness=Readiness.UNKNOWN,
            )
        )
    return findings


def _identity_finding(asset: Asset, evidence: list[Evidence]) -> Finding | None:
    """Report an identity only when the adapter emitted exposure evidence."""
    records = [record for record in evidence if record.evidence_type == "ike.identity_exposed"]
    if not records:
        return None
    return _finding(
        asset,
        records,
        rule_id="ike.v1.aggressive.identity_exposed",
        finding_type="ike.aggressive.identity_exposed",
        title="IKEv1 aggressive mode exposed responder identity",
        description=(
            "The probe observed key exchange, nonce, and identity payloads before authentication. "
            "The identity value is intentionally excluded from logs and public evidence."
        ),
        severity=Severity.HIGH,
        readiness=Readiness.CLASSICALLY_WEAK,
    )


def _psk_exposure_finding(asset: Asset, evidence: list[Evidence]) -> Finding | None:
    """Report offline PSK-cracking exposure without retaining the material."""
    records = [record for record in evidence if record.evidence_type == "ike.psk_hash_exposed"]
    if not records:
        return None
    return _finding(
        asset,
        records,
        rule_id="ike.v1.aggressive.psk_hash_exposed",
        finding_type="ike.aggressive.psk_hash_exposed",
        title="IKEv1 Aggressive Mode PSK hash exposed",
        description=(
            "The response contained parameters sufficient for offline PSK guessing. "
            "Values are omitted from scan output."
        ),
        severity=Severity.HIGH,
        readiness=Readiness.CLASSICALLY_WEAK,
    )


def _prohibited_transport_finding(asset: Asset, records: list[Evidence]) -> Finding | None:
    """Build the RFC 8247 prohibited-transform finding when evidence exists."""
    if not records:
        return None
    names = sorted({record.algorithm or "unknown" for record in records})
    return _finding(
        asset,
        records,
        rule_id="ike.transport.prohibited",
        finding_type="ike.transport.weak",
        title=f"Prohibited IKE algorithm reported ({', '.join(names)})",
        description=(
            "The tool reported an encryption, PRF, or integrity algorithm that RFC 8247 marks "
            "MUST NOT for IKEv2. IKEv1 remains Historic under RFC 9395."
        ),
        severity=Severity.HIGH,
        readiness=Readiness.CLASSICALLY_WEAK,
    )


def _legacy_transport_finding(asset: Asset, records: list[Evidence]) -> Finding | None:
    """Build the legacy 3DES finding when evidence exists."""
    if not records:
        return None
    return _finding(
        asset,
        records,
        rule_id="ike.transport.legacy_3des",
        finding_type="ike.transport.weak",
        title="Legacy 3DES algorithm reported",
        description=(
            "The tool reported 3DES. RFC 8247 downgraded ENCR_3DES to MAY for IKEv2; "
            "its 64-bit block size warrants migration to an AEAD algorithm."
        ),
        severity=Severity.MEDIUM,
        readiness=Readiness.CLASSICALLY_WEAK,
    )


def _transport_findings(asset: Asset, evidence: list[Evidence]) -> list[Finding]:
    """Classify reported encryption, PRF, and integrity transforms."""
    algorithms = [
        record
        for record in evidence
        if record.evidence_type in {"ike.cipher", "ike.prf", "ike.integrity"}
    ]
    prohibited = [
        record for record in algorithms if _algorithm_name(record).upper() in _PROHIBITED_ALGORITHMS
    ]
    legacy = [
        record for record in algorithms if _algorithm_name(record).upper() in _LEGACY_ALGORITHMS
    ]
    candidates = (
        _prohibited_transport_finding(asset, prohibited),
        _legacy_transport_finding(asset, legacy),
    )
    return [finding for finding in candidates if finding is not None]


def _weak_dh_finding(asset: Asset, records: list[Evidence], *, prohibited: bool) -> Finding | None:
    """Build one severity-calibrated weak Diffie-Hellman finding."""
    if not records:
        return None
    identifiers = _sorted_group_identifiers(records)
    return _finding(
        asset,
        records,
        rule_id="ike.dh.weak",
        finding_type="ike.kex.weak",
        title=f"Weak IKE Diffie-Hellman group reported ({', '.join(identifiers)})",
        description=(
            "RFC 8247 marks groups 1 and 22 MUST NOT and groups 2, 5, 23, and 24 SHOULD NOT "
            "for IKEv2. This tool-reported transform does not prove final negotiation."
        ),
        severity=Severity.HIGH if prohibited else Severity.MEDIUM,
        readiness=Readiness.CLASSICALLY_WEAK,
    )


def _pq_dh_finding(asset: Asset, records: list[Evidence]) -> Finding | None:
    """Inventory reported ML-KEM identifiers without upgrading readiness."""
    if not records:
        return None
    labels = sorted(
        {
            label
            for record in records
            if record.ike_group_id is not None
            for label in (_ML_KEM_GROUPS[record.ike_group_id],)
        }
    )
    return _finding(
        asset,
        records,
        rule_id="ike.pq.transform_reported",
        finding_type="ike.pq.tool_reported",
        title=f"ML-KEM transform identifier reported ({', '.join(labels)})",
        description=(
            "The identifier is recorded verbatim. draft-ietf-ipsecme-ikev2-mlkem-09 is not "
            "an RFC, and stock ike-scan cannot prove RFC 9370 additional key exchange completion. "
            "Readiness and HNDL exposure stay unknown."
        ),
        severity=Severity.INFO,
        readiness=Readiness.UNKNOWN,
    )


def _classical_dh_finding(asset: Asset, records: list[Evidence]) -> Finding | None:
    """Report the quantum axis for named classical IKE groups."""
    if not records:
        return None
    identifiers = _sorted_group_identifiers(records)
    return _finding(
        asset,
        records,
        rule_id="ike.kex.classical",
        finding_type="ike.kex.classical",
        title=f"Classical IKE key exchange reported ({', '.join(identifiers)})",
        description=(
            "The responder transform reported a classical Diffie-Hellman group. A quantum "
            "computer could break recorded classical key establishment; authenticated tunnel "
            "posture remains outside this unauthenticated probe."
        ),
        severity=Severity.LOW,
        readiness=Readiness.QUANTUM_VULNERABLE,
    )


def _group_records(evidence: list[Evidence]) -> list[Evidence]:
    """Return tool-reported IKE key-exchange records."""
    return [record for record in evidence if record.evidence_type == "ike.dh_group"]


def _sorted_group_identifiers(records: list[Evidence]) -> list[str]:
    """Return unique numeric group identifiers in numeric order."""
    identifiers = {record.ike_group_id for record in records if record.ike_group_id is not None}
    return [str(identifier) for identifier in sorted(identifiers)]


def _partition_groups(
    groups: list[Evidence],
) -> tuple[list[Evidence], list[Evidence], list[Evidence], list[Evidence]]:
    """Partition group evidence across independent policy axes."""
    prohibited: list[Evidence] = []
    discouraged: list[Evidence] = []
    classical: list[Evidence] = []
    post_quantum: list[Evidence] = []
    for record in groups:
        identifier = record.ike_group_id
        if identifier in _PROHIBITED_DH_GROUPS:
            prohibited.append(record)
        if identifier in _DISCOURAGED_DH_GROUPS:
            discouraged.append(record)
        if identifier in _CLASSICAL_DH_GROUPS:
            classical.append(record)
        if identifier in _ML_KEM_GROUPS:
            post_quantum.append(record)
    return prohibited, discouraged, classical, post_quantum


def _dh_findings(asset: Asset, evidence: list[Evidence]) -> list[Finding]:
    """Build separate quantum, weak-classical, and PQ inventory findings."""
    groups = _group_records(evidence)
    prohibited, discouraged, classical, post_quantum = _partition_groups(groups)
    candidates = (
        _classical_dh_finding(asset, classical),
        _weak_dh_finding(asset, prohibited + discouraged, prohibited=bool(prohibited)),
        _pq_dh_finding(asset, post_quantum),
    )
    return [finding for finding in candidates if finding is not None]


def _notify_finding(asset: Asset, evidence: list[Evidence]) -> Finding | None:
    """Report explicit proposal rejection without inferring accepted posture."""
    records = [record for record in evidence if record.evidence_type == "ike.notify"]
    if not records:
        return None
    names = sorted({record.algorithm or "NOTIFY" for record in records})
    return _finding(
        asset,
        records,
        rule_id="ike.proposal.rejected",
        finding_type="ike.proposal.rejected",
        title=f"IKE responder rejected the probe proposal ({', '.join(names)})",
        description="An explicit responder NOTIFY proves presence while leaving algorithm posture unknown.",
        severity=Severity.INFO,
        readiness=Readiness.UNKNOWN,
    )


def classify_ike(asset: Asset, evidence: list[Evidence]) -> list[Finding]:
    """Return IKE findings with classical hygiene separated from quantum posture."""
    findings = _protocol_findings(asset, evidence)
    findings.extend(_transport_findings(asset, evidence))
    findings.extend(_dh_findings(asset, evidence))
    for optional in (
        _identity_finding(asset, evidence),
        _psk_exposure_finding(asset, evidence),
        _notify_finding(asset, evidence),
    ):
        if optional is not None:
            findings.append(optional)
    return findings
