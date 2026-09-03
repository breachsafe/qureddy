# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Opt-in IKE acceptance tests against the authorized local responder."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import NoReturn

import pytest
from typer.testing import CliRunner

from qureddy.cli import app
from qureddy.core.ciphers import cipher_classical_bits
from qureddy.core.models import HndlExposure, PqcSupport, ScanResult
from qureddy.core.targets import parse_ike_target
from qureddy.scanners.ike.adapter import IkeScanAdapter
from qureddy.scanners.ike.parser import parse_ike_scan_output
from qureddy.scanners.ike.scanner import IKEScanner
from qureddy.scanners.ike.types import IKEMode, IKEParseStatus
from tests.ike_lab._guard import LabOutcome, evaluate_lab


def _unmet(reason: str) -> NoReturn:
    """Report an absent lab precondition as skipped, not failed (#740)."""
    pytest.skip(reason)


_PSKCRACK_MATERIAL = re.compile(r"(?i)(?:[0-9a-f]{2,}:){8}[0-9a-f]{2,}")


def _ike_scan_path() -> str:
    """Require the real stock executable used by the product boundary."""
    configured = os.environ.get("QUREDDY_IKE_SCAN")
    resolved = shutil.which(configured or "ike-scan")
    if resolved is None:
        _unmet("real ike-scan executable is required for live IKE acceptance tests")
    return resolved


def _target() -> str:
    """Return the explicitly overridable authorized live target."""
    return os.environ.get("QUREDDY_IKE_LIVE_TARGET", "127.0.0.1")


@pytest.fixture(scope="module")
def live_responder() -> None:
    """Require an authorized responder, not just a reflected packet (#740).

    ``ike-scan`` against loopback on matching source and destination ports gets
    its own request back when nothing is bound to UDP/500, so tool presence does
    not prove a responder exists. UDP/500 is privileged, which rules out a bind
    probe, so the check is the product's own classification. ``evaluate_lab``
    holds that decision and is unit tested in the hermetic lane.
    """
    scanner = IKEScanner(IkeScanAdapter(_ike_scan_path()))
    result = scanner.scan(parse_ike_target(_target()), timeout_seconds=2)
    verdict = evaluate_lab(result.evidence, status=result.scan.status, target=_target())
    if verdict.outcome is LabOutcome.RUN:
        return
    if verdict.outcome is LabOutcome.FAIL:
        pytest.fail(verdict.reason)
    _unmet(verdict.reason)


@pytest.fixture(scope="module")
def live_result(live_responder: None) -> ScanResult:
    """Run the production scanner once against the real responder."""
    scanner = IKEScanner(IkeScanAdapter(_ike_scan_path()), nat_t=True)
    return scanner.scan(parse_ike_target(_target()), timeout_seconds=2)


@pytest.fixture(scope="module")
def direct_live_result(live_responder: None) -> ScanResult:
    """Run direct IKE with the production source-port default."""
    scanner = IKEScanner(IkeScanAdapter(_ike_scan_path()))
    return scanner.scan(parse_ike_target(_target()), timeout_seconds=2)


@pytest.fixture(scope="module")
def psk_live_result() -> ScanResult:
    """Probe the authorized plain-IKE weak responder used for PSK exposure."""
    target = os.environ.get("QUREDDY_IKE_PSK_TARGET", "127.0.0.1:4500")
    source_port = int(os.environ.get("QUREDDY_IKE_PSK_SOURCE_PORT", "40501"))
    scanner = IKEScanner(IkeScanAdapter(_ike_scan_path(), source_port=source_port))
    return scanner.scan(parse_ike_target(target), timeout_seconds=2)


def test_live_direct_probe_uses_udp_500_and_detects_responder(
    direct_live_result: ScanResult,
) -> None:
    """Prevent ephemeral source ports from hiding real gateways (#719)."""
    responded = [
        record
        for record in direct_live_result.evidence
        if record.evidence_type == "ike.mode.responded"
    ]
    source_ports = {
        probe.command.args[probe.command.args.index("--sport") + 1]
        for record in direct_live_result.evidence
        if (probe := record.probe_result) is not None and "--sport" in probe.command.args
    }

    assert direct_live_result.scan.status == "completed"
    assert direct_live_result.scan.total_attempts == 3
    assert len(responded) == 3
    assert source_ports == {"500"}


def test_live_dual_stack_responder_has_no_duplicate_mode_attempts(
    live_result: ScanResult,
) -> None:
    """Probe UDP 500 only as fallback when NAT-T answered that mode (#716)."""
    responded = [
        record for record in live_result.evidence if record.evidence_type == "ike.mode.responded"
    ]

    assert live_result.scan.status == "completed"
    assert live_result.scan.total_attempts == 3
    assert len(responded) == 3
    assert all("transport=nat_t" in record.notes for record in responded)


def test_live_result_reports_classical_quantum_exposure(live_result: ScanResult) -> None:
    """Prove strong classical groups still drive the quantum axis (#713)."""
    rules = {finding.rule_id for finding in live_result.findings}

    assert "ike.kex.classical" in rules
    assert live_result.summary.interpretation is not None
    assert live_result.summary.interpretation.axes.pqc_support is PqcSupport.CLASSICAL_ONLY_OBSERVED
    assert live_result.summary.interpretation.hndl_exposure is HndlExposure.UNKNOWN
    summary = live_result.summary.interpretation.display.evaluation.summary
    assert "Overall IPsec HNDL exposure could not be determined" in summary
    assert live_result.dependencies[0].version == "1.9.5"
    observed = live_result.summary.interpretation.display.evaluation.observed_facts
    assert all("negotiated" not in fact.lower() for fact in observed)


def test_live_ikev2_transforms_drive_inventory_and_weak_findings(
    live_result: ScanResult,
) -> None:
    """Keep IKEv2-only facts and prohibited algorithms visible (#684/#688)."""
    ikev2_groups = {
        record.ike_group_id
        for record in live_result.evidence
        if record.evidence_type == "ike.dh_group" and record.protocol_version == "IKEv2"
    }
    algorithms = {
        record.algorithm
        for record in live_result.evidence
        if record.protocol_version == "IKEv2" and record.algorithm is not None
    }
    findings = {finding.rule_id: finding for finding in live_result.findings}
    evidence_by_id = {record.id: record for record in live_result.evidence}

    assert {2, 5, 14} <= ikev2_groups
    assert {"DES", "HMAC_MD5", "HMAC_MD5_96"} <= algorithms
    assert {"ike.kex.classical", "ike.transport.prohibited"} <= findings.keys()
    prohibited_algorithms = {
        evidence_by_id[evidence_id].algorithm
        for evidence_id in findings["ike.transport.prohibited"].evidence_ids
    }
    assert "HMAC_MD5_96" in prohibited_algorithms


def test_live_ikev1_findings_require_identity_and_cite_rfc9395(
    live_result: ScanResult,
) -> None:
    """Bind identity exposure to real payloads and the correct Historic RFC (#680/#685)."""
    findings = {finding.rule_id: finding for finding in live_result.findings}
    historic = findings["ike.v1.present"]
    identity = findings["ike.v1.aggressive.identity_exposed"]
    evidence = {record.id: record for record in live_result.evidence}

    assert "RFC 9395" in historic.description
    assert "RFC 8247" not in historic.description
    assert all(
        evidence[item].evidence_type == "ike.identity_exposed" for item in identity.evidence_ids
    )


def test_live_psk_hash_exposure_is_canonical_but_material_is_omitted(
    psk_live_result: ScanResult,
) -> None:
    """Prove stock ike-scan drives #763 without leaking its nine-field output."""
    findings = {finding.rule_id: finding for finding in psk_live_result.findings}
    exposed = findings["ike.v1.aggressive.psk_hash_exposed"]
    evidence = {record.id: record for record in psk_live_result.evidence}
    serialized = psk_live_result.model_dump_json()

    assert exposed.severity.value == "high"
    assert all(
        evidence[item].evidence_type == "ike.psk_hash_exposed" for item in exposed.evidence_ids
    )
    assert _PSKCRACK_MATERIAL.search(serialized) is None
    assert "qureddy-ike-" not in serialized


def test_live_findings_only_reference_emitted_evidence(live_result: ScanResult) -> None:
    """Prevent fabricated or dangling finding evidence identifiers (#683)."""
    evidence_ids = {record.id for record in live_result.evidence}

    assert all(set(finding.evidence_ids) <= evidence_ids for finding in live_result.findings)


def test_real_ikev1_output_preserves_space_form_key_length(live_responder: None) -> None:
    """Parse actual ike-scan IKEv1 multiline output with AES key length (#715)."""
    command = [
        _ike_scan_path(),
        "--retry",
        "2",
        "--timeout",
        "1000",
        "--nat-t",
        "--sport",
        "4500",
        "--dport",
        "4500",
        "--multiline",
        "--trans=7/256,1,1,14",
        parse_ike_target(_target()).host,
    ]
    completed = subprocess.run(  # noqa: S603 - resolved binary, parsed host, list-form argv.
        command,
        capture_output=True,
        check=False,
        shell=False,
        timeout=5,
    )
    output = completed.stdout.decode("utf-8", errors="replace")

    assert completed.returncode == 0
    assert "Main Mode Handshake returned" in output
    assert "Enc=AES" in output
    assert "KeyLength=256" in output
    response = parse_ike_scan_output(IKEMode.IKEV1_MAIN, text=output)
    assert response.status is IKEParseStatus.RESPONDED
    assert response.encryption == ("AES_256",)
    assert cipher_classical_bits(response.encryption[0]) == 256


def test_real_cli_writes_every_output_from_one_scan(live_responder: None, tmp_path: Path) -> None:
    """Exercise Rich, JSON, JSONL, and CBOM through one real CLI scan."""
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "ike",
            _target(),
            "--ike-scan",
            _ike_scan_path(),
            "--nat-t",
            "--timeout",
            "2",
            "--output-dir",
            str(tmp_path),
            "--deterministic",
            "--quiet",
        ],
    )

    assert result.exit_code == 0, result.output
    outputs = {path.name for path in tmp_path.iterdir() if path.is_file()}
    assert outputs == {"scan.json", "scan.cdx.json", "scan.jsonl", "scan.rich.txt"}
    canonical = json.loads((tmp_path / "scan.json").read_text())
    cbom = json.loads((tmp_path / "scan.cdx.json").read_text())
    jsonl = [json.loads(line) for line in (tmp_path / "scan.jsonl").read_text().splitlines()]
    rich = (tmp_path / "scan.rich.txt").read_text()
    assert canonical["scan"]["scanner_name"] == "ike"
    assert canonical["scan"]["total_attempts"] == 3
    assert jsonl[-1]["scan_id"] == canonical["scan"]["scan_id"]
    assert jsonl[-1]["status"] == canonical["scan"]["status"]
    tools = {component["name"]: component for component in cbom["metadata"]["tools"]["components"]}
    assert tools["qureddy"]["version"]
    assert tools["ike-scan"]["version"] == "1.9.5"
    component_names = {component["name"] for component in cbom["components"]}
    assert {"AES_CBC_256", "HMAC_MD5", "modp2048"} <= component_names
    assert "IKE" in rich
    assert "IKE negotiated" not in rich
