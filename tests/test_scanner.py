# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Tests for TLSScanner orchestration that don't require live network."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest

import qureddy.scanners.tls.scanner as scanner_module
from qureddy.core.errors import LocalOpenSSLMissing
from qureddy.core.models import (
    Asset,
    Confidence,
    Evidence,
    FailureCategory,
    Finding,
    ObservationType,
    OpenSSLDependency,
    ProbeCommand,
    ProbeResult,
    ProbeRole,
    Readiness,
    ScanMetadata,
    ScanResult,
    ScanTarget,
    Severity,
)
from qureddy.core.policy import classify_evidence
from qureddy.scanners.tls._evidence import build_asset, evidence_from_probe
from qureddy.scanners.tls.cert_probe import CertificateInfo
from qureddy.scanners.tls.openssl_probe import HYBRID_GROUP
from qureddy.scanners.tls.scanner import TLSScanner, _build_summary


class TestTLSScannerOrchestration:
    """Hermetic coverage of the full-scan orchestration branches."""

    @staticmethod
    def _target() -> ScanTarget:
        return ScanTarget(
            original_input="example.invalid",
            host="example.invalid",
            port=443,
            sni="example.invalid",
            locator="tls://example.invalid:443",
        )

    def test_reachable_target_collects_legacy_and_certificate_evidence(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        scanner = TLSScanner(openssl_path="/fixture/openssl")
        dependency = OpenSSLDependency(
            path="/fixture/openssl",
            version="3.5.7",
            supports_tls13_groups=True,
            supports_x25519mlkem768=True,
        )
        monkeypatch.setattr(
            scanner, "_check_capability", lambda _timeout: (dependency.path, dependency)
        )
        legacy_dependency = OpenSSLDependency(
            name="openssl-legacy", path="/fixture/legacy", version="1.0.2u"
        )
        monkeypatch.setattr(
            scanner,
            "_check_legacy_capability",
            lambda _timeout: (legacy_dependency.path, legacy_dependency),
        )
        monkeypatch.setattr(scanner, "_collect_evidence", lambda **_kwargs: ([], 0))
        monkeypatch.setattr(scanner, "_collect_legacy_evidence", lambda **_kwargs: ([], []))

        def collect_cert(**kwargs: object) -> tuple[Evidence, tuple[Finding, ...]]:
            asset = kwargs["asset"]
            assert isinstance(asset, Asset)
            return (
                Evidence(
                    id="ev-cert",
                    asset_id=asset.id,
                    evidence_type="tls.cert.signature",
                    observation_type=ObservationType.NOT_TESTABLE,
                    source="fixture",
                ),
                (),
            )

        monkeypatch.setattr(scanner, "_collect_cert_evidence", collect_cert)
        result = scanner.scan(self._target(), timeout_seconds=1)
        assert result.scan.status == "completed"
        assert result.scan.total_attempts == 1
        assert result.dependencies[1].version == "1.0.2u"
        assert result.evidence[0].id == "ev-cert"

    def test_unreachable_target_skips_supplemental_probes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        scanner = TLSScanner(openssl_path="/fixture/openssl")
        dependency = OpenSSLDependency(
            path="/fixture/openssl",
            version="3.5.7",
            supports_tls13_groups=True,
            supports_x25519mlkem768=True,
        )
        target = self._target()
        asset = build_asset(target)
        failure = Evidence(
            id="ev-connect",
            asset_id=asset.id,
            evidence_type="tls.probe.failure",
            observation_type=ObservationType.OBSERVED,
            source="fixture",
            failure_category=FailureCategory.TARGET_CONNECT_FAILED,
        )
        monkeypatch.setattr(
            scanner, "_check_capability", lambda _timeout: (dependency.path, dependency)
        )
        monkeypatch.setattr(scanner, "_collect_evidence", lambda **_kwargs: ([failure], 1))

        def unexpected(**_kwargs: object) -> None:
            pytest.fail("supplemental probe ran for unreachable target")

        monkeypatch.setattr(scanner, "_collect_legacy_evidence", unexpected)
        monkeypatch.setattr(scanner, "_collect_cert_evidence", unexpected)
        result = scanner.scan(target, timeout_seconds=1)
        assert result.scan.status == "completed"
        assert result.scan.total_attempts == 1
        assert result.evidence[0].failure_category is FailureCategory.TARGET_CONNECT_FAILED

    def test_certificate_collection_covers_missing_and_observed_paths(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        target = self._target()
        asset = build_asset(target)
        monkeypatch.setattr(scanner_module, "fetch_certificate_pem", lambda *_args, **_kwargs: "")
        evidence, findings = TLSScanner._collect_cert_evidence(  # noqa: SLF001
            target=target,
            asset=asset,
            openssl_path="/fixture/openssl",
            timeout_seconds=1,
        )
        assert findings == ()
        assert evidence.observation_type is ObservationType.NOT_TESTABLE

        certificate = CertificateInfo(
            subject="CN=test",
            issuer="CN=issuer",
            not_before="Jul 23 16:01:49 2026 GMT",
            not_after="Oct 21 16:55:01 2026 GMT",
            serial="01",
            signature_algorithm="sha256WithRSAEncryption",
            public_key_summary="Public-Key: (2048 bit)",
            is_self_signed=False,
            is_post_quantum_signature=False,
            public_key_algorithm="rsaEncryption",
            public_key_bits=2048,
        )
        monkeypatch.setattr(
            scanner_module, "fetch_certificate_pem", lambda *_args, **_kwargs: "fixture pem"
        )
        monkeypatch.setattr(
            scanner_module, "parse_certificate", lambda *_args, **_kwargs: certificate
        )
        evidence, findings = TLSScanner._collect_cert_evidence(  # noqa: SLF001
            target=target,
            asset=asset,
            openssl_path="/fixture/openssl",
            timeout_seconds=1,
        )
        assert evidence.observation_type is ObservationType.OBSERVED
        assert evidence.algorithm == "sha256WithRSAEncryption"
        assert evidence.primitive == "signature"
        assert evidence.nist_quantum_security_level == 0
        assert evidence.model_dump(mode="json")["certificate"] == {
            "subject": "CN=test",
            "issuer": "CN=issuer",
            "not_valid_before": "2026-07-23T16:01:49+00:00",
            "not_valid_after": "2026-10-21T16:55:01+00:00",
            "serial_number": "01",
            "signature_algorithm": "sha256WithRSAEncryption",
            "public_key_algorithm": "rsaEncryption",
            "public_key_bits": 2048,
            "is_self_signed": False,
            "is_post_quantum_signature": False,
        }
        assert len(findings) == 1
        assert findings[0].algorithm == "sha256WithRSAEncryption"
        assert findings[0].primitive == "signature"
        assert findings[0].nist_quantum_security_level == 0

        expired_md5 = replace(
            certificate,
            not_after="Jan 1 00:00:00 2007 GMT",
            signature_algorithm="md5WithRSAEncryption",
        )
        monkeypatch.setattr(
            scanner_module, "parse_certificate", lambda *_args, **_kwargs: expired_md5
        )
        evidence, findings = TLSScanner._collect_cert_evidence(  # noqa: SLF001
            target=target,
            asset=asset,
            openssl_path="/fixture/openssl",
            timeout_seconds=1,
            now=datetime(2026, 9, 6, tzinfo=UTC),
        )
        assert evidence.observation_type is ObservationType.OBSERVED
        assert {finding.finding_type for finding in findings} == {
            "tls.cert.classical_signature",
            "tls.cert.classical_signature_weak",
            "tls.cert.expired",
        }
        assert {finding.severity for finding in findings} == {
            Severity.INFO,
            Severity.HIGH,
            Severity.CRITICAL,
        }

        sha1_certificate = replace(
            certificate,
            signature_algorithm="sha1WithRSAEncryption",
        )
        monkeypatch.setattr(
            scanner_module, "parse_certificate", lambda *_args, **_kwargs: sha1_certificate
        )
        _evidence, findings = TLSScanner._collect_cert_evidence(  # noqa: SLF001
            target=target,
            asset=asset,
            openssl_path="/fixture/openssl",
            timeout_seconds=1,
            now=datetime(2026, 9, 6, tzinfo=UTC),
        )
        assert "tls.cert.classical_signature_weak" in {finding.finding_type for finding in findings}

        unknown_certificate = replace(certificate, signature_algorithm="vendorSignature42")
        monkeypatch.setattr(
            scanner_module, "parse_certificate", lambda *_args, **_kwargs: unknown_certificate
        )
        evidence, findings = TLSScanner._collect_cert_evidence(  # noqa: SLF001
            target=target,
            asset=asset,
            openssl_path="/fixture/openssl",
            timeout_seconds=1,
        )
        assert evidence.algorithm == "vendorSignature42"
        assert evidence.primitive == "signature"
        assert evidence.parameter_set_identifier is None
        assert evidence.nist_quantum_security_level is None
        assert len(findings) == 1
        assert findings[0].algorithm == "vendorSignature42"
        assert findings[0].primitive == "signature"
        assert findings[0].nist_quantum_security_level is None

        unknown_certificate = replace(certificate, signature_algorithm="UNKNOWN")
        monkeypatch.setattr(
            scanner_module, "parse_certificate", lambda *_args, **_kwargs: unknown_certificate
        )
        _evidence, findings = TLSScanner._collect_cert_evidence(  # noqa: SLF001
            target=target,
            asset=asset,
            openssl_path="/fixture/openssl",
            timeout_seconds=1,
        )
        assert findings == ()

        def missing_openssl(*_args: object, **_kwargs: object) -> str:
            raise LocalOpenSSLMissing("fixture openssl missing")

        monkeypatch.setattr(scanner_module, "fetch_certificate_pem", missing_openssl)
        evidence, findings = TLSScanner._collect_cert_evidence(  # noqa: SLF001
            target=target,
            asset=asset,
            openssl_path="/fixture/openssl",
            timeout_seconds=1,
        )
        assert findings == ()
        assert evidence.observation_type is ObservationType.NOT_TESTABLE


class TestSummaryFailureCategoryPreservation:
    """The summary must surface the exact category, not collapse rules."""

    def _make_result_with_local_failure(
        self,
        category: FailureCategory,
    ) -> ScanResult:
        target = ScanTarget(
            original_input="example.com",
            host="example.com",
            port=443,
            sni="example.com",
            locator="tls://example.com:443",
        )
        asset = Asset(
            id="asset-1",
            asset_type="tls.endpoint",
            locator=target.locator,
            display_name="example.com:443",
        )
        ev = Evidence(
            id="ev-1",
            asset_id=asset.id,
            evidence_type="tls.capability",
            observation_type=ObservationType.NOT_TESTABLE,
            source="qureddy.openssl_probe",
            failure_category=category,
        )
        finding = Finding(
            id="f-1",
            asset_id=asset.id,
            evidence_ids=("ev-1",),
            rule_id="tls.hybrid.not_testable",
            finding_type="tls.kex.not_testable",
            title="not testable",
            description="d",
            severity=Severity.INFO,
            readiness=Readiness.UNKNOWN,
            confidence=Confidence.HIGH,
        )
        summary = _build_summary(target, [finding], [ev])
        return ScanResult(
            scan=ScanMetadata(
                scan_id="scan-1",
                started_at=datetime(2026, 4, 26, tzinfo=UTC),
                completed_at=datetime(2026, 4, 26, tzinfo=UTC),
                status="x",
            ),
            target=target,
            dependencies=(OpenSSLDependency(failure_category=category),),
            assets=(asset,),
            evidence=(ev,),
            findings=(finding,),
            summary=summary,
        )

    def test_local_openssl_too_old_preserved(self) -> None:
        result = self._make_result_with_local_failure(
            FailureCategory.LOCAL_OPENSSL_TOO_OLD,
        )
        assert result.summary.failure_category is FailureCategory.LOCAL_OPENSSL_TOO_OLD

    def test_local_openssl_lacks_group_preserved(self) -> None:
        result = self._make_result_with_local_failure(
            FailureCategory.LOCAL_OPENSSL_LACKS_GROUP,
        )
        assert result.summary.failure_category is FailureCategory.LOCAL_OPENSSL_LACKS_GROUP

    def test_local_openssl_missing_preserved(self) -> None:
        result = self._make_result_with_local_failure(
            FailureCategory.LOCAL_OPENSSL_MISSING,
        )
        assert result.summary.failure_category is FailureCategory.LOCAL_OPENSSL_MISSING

    def test_probe_failure_categories_preserved(self) -> None:
        """target_connect_failed and tls_handshake_failed are distinct."""
        target = ScanTarget(
            original_input="t",
            host="t",
            port=443,
            sni="t",
            locator="tls://t:443",
        )
        asset = Asset(
            id="a",
            asset_type="tls.endpoint",
            locator=target.locator,
            display_name="t:443",
        )

        for category in (
            FailureCategory.TARGET_CONNECT_FAILED,
            FailureCategory.TLS_HANDSHAKE_FAILED,
            FailureCategory.MIDDLEBOX_OR_MTU_FAILURE,
            FailureCategory.PARSE_NO_GROUP,
        ):
            ev = Evidence(
                id=f"ev-{category.value}",
                asset_id=asset.id,
                evidence_type="tls.probe.failure",
                observation_type=ObservationType.OBSERVED,
                source="openssl",
                probe_result=ProbeResult(
                    command=ProbeCommand(
                        executable="openssl",
                        args=(),
                        timeout_seconds=30,
                    ),
                    return_code=1,
                    stdout_sha256="0" * 64,
                    stderr_sha256="0" * 64,
                    duration_ms=1,
                ),
                failure_category=category,
            )
            finding = Finding(
                id=f"f-{category.value}",
                asset_id=asset.id,
                evidence_ids=(ev.id,),
                rule_id="tls.hybrid.probe_failed",
                finding_type="tls.kex.probe_failed",
                title="t",
                description="d",
                severity=Severity.INFO,
                readiness=Readiness.UNKNOWN,
                confidence=Confidence.MEDIUM,
            )
            summary = _build_summary(target, [finding], [ev])
            assert summary.failure_category is category, (
                f"expected {category} preserved, got {summary.failure_category}"
            )


class TestSummaryFailureCategorySupersededByRetrySuccess:
    """Issue #241: a later successful retry must clear an earlier failure category."""

    def test_hybrid_negotiated_after_earlier_failed_attempt_clears_failure_category(
        self,
    ) -> None:
        target = ScanTarget(
            original_input="flaky.example",
            host="flaky.example",
            port=443,
            sni=None,
            locator="tls://flaky.example:443",
        )
        asset = build_asset(target)

        attempt1 = ProbeResult(
            command=ProbeCommand(
                executable="openssl", args=("s_client", "-groups", HYBRID_GROUP), timeout_seconds=5
            ),
            return_code=1,
            stdout_sha256="0" * 64,
            stderr_sha256="0" * 64,
            duration_ms=1,
            attempt_number=1,
            failure_category=FailureCategory.TARGET_CONNECT_FAILED,
        )
        attempt2_stdout = (
            "Protocol version: TLSv1.3\n"
            "Ciphersuite: TLS_AES_256_GCM_SHA384\n"
            "Negotiated TLS1.3 group: X25519MLKEM768\n"
        )
        attempt2 = ProbeResult(
            command=ProbeCommand(
                executable="openssl", args=("s_client", "-groups", HYBRID_GROUP), timeout_seconds=5
            ),
            return_code=0,
            stdout_sha256="0" * 64,
            stderr_sha256="0" * 64,
            parser_input=attempt2_stdout,
            duration_ms=1,
            attempt_number=2,
            failure_category=None,
        )

        ev1 = evidence_from_probe(
            asset=asset,
            probe=attempt1,
            expected_group=HYBRID_GROUP,
            probe_role=ProbeRole.HYBRID_READINESS,
        )
        ev2 = evidence_from_probe(
            asset=asset,
            probe=attempt2,
            expected_group=HYBRID_GROUP,
            probe_role=ProbeRole.HYBRID_READINESS,
        )
        evidence = [ev1, ev2]
        findings = classify_evidence(asset, evidence)
        summary = _build_summary(target, findings, evidence)

        assert summary.readiness is Readiness.TRANSITIONAL_HYBRID
        assert summary.failure_category is None

    def test_classical_control_success_does_not_clear_hybrid_failure(self) -> None:
        """Issue #836: a different probe's success cannot erase a timeout."""
        target = ScanTarget(
            original_input="split.example",
            host="split.example",
            port=443,
            sni=None,
            locator="tls://split.example:443",
        )
        asset = build_asset(target)
        hybrid_failure = Evidence(
            id="ev-hybrid-failure",
            asset_id=asset.id,
            evidence_type="tls.probe.failure",
            observation_type=ObservationType.OBSERVED,
            source="fixture",
            probe_role=ProbeRole.HYBRID_READINESS,
            failure_category=FailureCategory.TARGET_CONNECT_FAILED,
        )
        classical_success = Evidence(
            id="ev-classical-success",
            asset_id=asset.id,
            evidence_type="tls.negotiation",
            observation_type=ObservationType.NEGOTIATED,
            source="fixture",
            probe_role=ProbeRole.CLASSICAL_CONTROL,
            negotiated_group="X25519",
        )
        findings = [
            Finding(
                id="f-hybrid-failure",
                asset_id=asset.id,
                evidence_ids=(hybrid_failure.id,),
                rule_id="tls.hybrid.probe_failed",
                finding_type="tls.kex.probe_failed",
                title="hybrid probe failed",
                description="d",
                severity=Severity.INFO,
                readiness=Readiness.UNKNOWN,
                confidence=Confidence.MEDIUM,
            ),
            Finding(
                id="f-classical-success",
                asset_id=asset.id,
                evidence_ids=(classical_success.id,),
                rule_id="tls.classical.negotiated_x25519",
                finding_type="tls.kex.classical",
                title="classical control succeeded",
                description="d",
                severity=Severity.LOW,
                readiness=Readiness.QUANTUM_VULNERABLE,
                confidence=Confidence.HIGH,
            ),
        ]

        summary = _build_summary(target, findings, [hybrid_failure, classical_success])

        assert summary.failure_category is FailureCategory.TARGET_CONNECT_FAILED
