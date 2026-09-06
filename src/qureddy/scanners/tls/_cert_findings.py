# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Evidence/Finding builders for certificate signature and hygiene axes (#183, #789).

Issue #226 correction: this is the certificate's *issuer* signature axis
(chain-of-trust), not a live-handshake authentication claim — see cert_sig.py's
docstring for why those are different operations that can use different
algorithms. This module closes the wiring gap: the detection logic
(cert_sig.py, issue #7) existed but nothing called it, so the scan never
reported this axis and output hardcoded a false "remain classical" assertion
regardless of what the cert actually used.

Readiness is deliberately Readiness.NOT_APPLICABLE for both outcomes
(NOT_APPLICABLE is the lowest-precedence tier in _summary.py's
scan_readiness rollup, so it can never override the key-exchange axis's
verdict) — formally combining both axes into a single verdict is
issue #166's "quantum_ready" tier, out of scope here. This only makes
the axis visible and honest, not blindly asserted.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from qureddy.core.algorithm_profile import AlgorithmProfile, classify_signature_algorithm
from qureddy.core.certificate import CertificateObservation, parse_openssl_date
from qureddy.core.ids import new_id
from qureddy.core.models import (
    Asset,
    Confidence,
    Evidence,
    Finding,
    ObservationType,
    Readiness,
    Severity,
)
from qureddy.scanners.common.finding_types import (
    FINDING_TYPE_CLASSICAL_SIGNATURE,
    FINDING_TYPE_EXPIRED_CERTIFICATE,
    FINDING_TYPE_PQ_SIGNATURE,
    FINDING_TYPE_WEAK_CERTIFICATE_SIGNATURE,
)
from qureddy.scanners.tls.cert_sig import pqc_signature_standard

if TYPE_CHECKING:
    from qureddy.scanners.tls.cert_probe import CertificateInfo


# Named once here (the module that owns these finding_type values) so
# console.py's lookup can import them instead of re-typing the literal
# strings in a second place, where they could silently drift out of
# sync with a rename here.
def evidence_from_certificate(asset: Asset, certificate: CertificateInfo | None) -> Evidence:
    """One Evidence record for the cert axis — present even when the fetch failed.

    `certificate is None` means the independent cert probe didn't
    produce a usable PEM (timeout, connection refused, etc.) — still
    worth recording as "not inspected", per the issue's own guidance:
    never assert "classical" when the cert was never actually looked at.
    """
    if certificate is None:
        return Evidence(
            id=new_id("ev"),
            asset_id=asset.id,
            evidence_type="tls.cert.signature",
            observation_type=ObservationType.NOT_TESTABLE,
            source="qureddy.scanners.tls.cert_probe",
            notes=("certificate not fetched or unparseable",),
        )
    profile = classify_signature_algorithm(certificate.signature_algorithm) or AlgorithmProfile(
        "signature", None
    )
    observation = CertificateObservation(
        subject=certificate.subject,
        issuer=certificate.issuer,
        not_before=certificate.not_before,
        not_after=certificate.not_after,
        serial=certificate.serial,
        signature_algorithm=certificate.signature_algorithm,
        public_key_summary=certificate.public_key_summary,
        public_key_algorithm=certificate.public_key_algorithm,
        public_key_bits=certificate.public_key_bits,
        is_self_signed=certificate.is_self_signed,
        is_post_quantum_signature=certificate.is_post_quantum_signature,
    )
    return Evidence(
        id=new_id("ev"),
        asset_id=asset.id,
        evidence_type="tls.cert.signature",
        observation_type=ObservationType.OBSERVED,
        source="qureddy.scanners.tls.cert_sig",
        algorithm=certificate.signature_algorithm,
        primitive=profile.primitive,
        parameter_set_identifier=profile.parameter_set_identifier,
        nist_quantum_security_level=profile.nist_quantum_security_level,
        notes=(f"signature algorithm: {certificate.signature_algorithm}",),
        certificate_record=observation,
    )


def finding_from_certificate(
    asset: Asset, evidence: Evidence, certificate: CertificateInfo | None
) -> Finding | None:
    """A Finding reporting the cert axis, or None when the cert wasn't inspected.

    No Finding on a failed/missing fetch (evidence above already
    records that) — a finding implies a real observation to act on.
    """
    if certificate is None or certificate.signature_algorithm == "UNKNOWN":
        return None
    pq = certificate.is_post_quantum_signature
    return Finding(
        id=new_id("finding"),
        asset_id=asset.id,
        evidence_ids=(evidence.id,),
        rule_id="tls.cert.signature_algorithm",
        finding_type=FINDING_TYPE_PQ_SIGNATURE if pq else FINDING_TYPE_CLASSICAL_SIGNATURE,
        title=(
            f"Certificate issuer signature: {certificate.signature_algorithm}"
            + (" (post-quantum)" if pq else " (classical)")
        ),
        description=(
            f"Leaf certificate subject={certificate.subject!r} was issued using "
            f"{certificate.signature_algorithm} as the CA/issuer signature over "
            "the certificate. "
            + (
                "This is a NIST-standardized post-quantum signature algorithm "
                f"({pqc_signature_standard(certificate.signature_algorithm)}). "
                if pq
                else "This is a classical (non-post-quantum) signature algorithm. "
            )
            + "This describes the certificate's chain-of-trust signature only — "
            "it is NOT the live TLS handshake's authentication signature "
            "(CertificateVerify), which uses the leaf's own key and can use a "
            "different algorithm (issue #226)."
        ),
        severity=Severity.INFO,
        readiness=Readiness.NOT_APPLICABLE,
        confidence=Confidence.HIGH,
        algorithm=evidence.algorithm,
        primitive=evidence.primitive,
        parameter_set_identifier=evidence.parameter_set_identifier,
        nist_quantum_security_level=evidence.nist_quantum_security_level,
    )


def findings_from_certificate(
    asset: Asset,
    evidence: Evidence,
    certificate: CertificateInfo | None,
    *,
    now: datetime | None = None,
) -> tuple[Finding, ...]:
    """Return the certificate signature axis plus independently actionable hygiene findings."""
    if certificate is None:
        return ()
    primary = finding_from_certificate(asset, evidence, certificate)
    if primary is None:
        return ()
    findings = [primary]
    signature = certificate.signature_algorithm.lower()
    weak = _weak_signature_finding(primary, certificate, signature)
    if weak is not None:
        findings.append(weak)
    expired = _expired_certificate_finding(primary, certificate, now=now)
    if expired is not None:
        findings.append(expired)
    return tuple(findings)


def _weak_signature_finding(
    primary: Finding, certificate: CertificateInfo, signature: str
) -> Finding | None:
    """Build a hygiene finding for a deprecated or broken issuer signature."""
    if not any(marker in signature for marker in ("md5", "sha1", "sha-1")):
        return None
    return primary.model_copy(
        update={
            "id": new_id("finding"),
            "rule_id": "tls.cert.weak_signature_algorithm",
            "finding_type": FINDING_TYPE_WEAK_CERTIFICATE_SIGNATURE,
            "title": f"Weak certificate issuer signature: {certificate.signature_algorithm}",
            "description": (
                f"Leaf certificate subject={certificate.subject!r} uses "
                f"{certificate.signature_algorithm}, which is deprecated or collision-broken "
                "for certificate issuer signatures. Replace the certificate chain with a "
                "SHA-2-or-stronger signature algorithm."
            ),
            "severity": Severity.CRITICAL if "md5" in signature else Severity.HIGH,
            "readiness": Readiness.CLASSICALLY_WEAK,
        }
    )


def _expired_certificate_finding(
    primary: Finding, certificate: CertificateInfo, *, now: datetime | None
) -> Finding | None:
    """Build a hygiene finding when the observed certificate is expired."""
    not_after = parse_openssl_date(certificate.not_after)
    comparison_time = now or datetime.now(UTC)
    if not_after is None or not_after > comparison_time:
        return None
    return primary.model_copy(
        update={
            "id": new_id("finding"),
            "rule_id": "tls.cert.expired",
            "finding_type": FINDING_TYPE_EXPIRED_CERTIFICATE,
            "title": "Expired TLS certificate",
            "description": (
                f"Leaf certificate subject={certificate.subject!r} expired at "
                f"{not_after.isoformat()}. Replace it before relying on this endpoint."
            ),
            "severity": Severity.HIGH,
            "readiness": Readiness.CLASSICALLY_WEAK,
        }
    )
