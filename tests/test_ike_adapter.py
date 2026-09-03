# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Hermetic integration tests for the stock ike-scan adapter boundary."""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

from qureddy.core.contracts import CollectionFailureKind, ScanSource, SourceKind
from qureddy.core.models import FailureCategory, ObservationType, ProbeCommand, ProbeResult
from qureddy.scanners.ike.adapter import (
    IkeScanAdapter,
    _output_failure_category,
    _process_failure,
    _process_response,
    _response_evidence,
)
from qureddy.scanners.ike.execution import ProcessOutput
from qureddy.scanners.ike.parser import ParsedIKEResponse
from qureddy.scanners.ike.types import IKEMode, IKEParseStatus

_FIXTURES = Path(__file__).parent / "fixtures" / "ike"


def _tool(tmp_path: Path, body: str) -> str:
    """Create a real executable child process for an adapter integration test."""
    script = tmp_path / "ike_scan_fixture.py"
    script.write_text(f"import sys\n{body}\n")
    if os.name == "nt":
        path = tmp_path / "ike-scan-fixture.cmd"
        path.write_text(f'@"{sys.executable}" "{script}" %*\n')
        return str(path)
    path = tmp_path / "ike-scan-fixture"
    path.write_text(f"#!{sys.executable}\n{script.read_text()}")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return str(path)


def _source(*, mode: str = "ikev2", locator: str = "ike://127.0.0.1:500") -> ScanSource:
    return ScanSource(
        kind=SourceKind.ENDPOINT,
        protocol="ike",
        locator=locator,
        metadata={"mode": mode, "asset_id": "asset-1", "nat_t": "false"},
    )


def _probe(category: FailureCategory | None = None) -> ProbeResult:
    return ProbeResult(
        command=ProbeCommand(executable="ike-scan", args=(), timeout_seconds=1),
        return_code=0,
        stdout_sha256="0" * 64,
        stderr_sha256="0" * 64,
        parser_input="",
        duration_ms=1,
        failure_category=category,
    )


def test_adapter_runs_real_executable_and_normalizes_response(tmp_path: Path) -> None:
    binary = _tool(
        tmp_path,
        """if "--version" in sys.argv:
    print("ike-scan 9.9")
    raise SystemExit
print("Handshake returned (1 transforms) Encr=AES KeyLength=256 Prf=SHA2 Integ=HMAC_SHA2 Group=14:modp2048")""",
    )
    adapter = IkeScanAdapter(binary)

    result = adapter.run(_source(), timeout_seconds=1)

    assert adapter.available()
    assert adapter.version == "9.9"
    assert adapter.dependency().failure_category is None
    assert result.failure is None
    assert {record.evidence_type for record in result.evidence} == {
        "ike.mode.responded",
        "ike.cipher",
        "ike.prf",
        "ike.integrity",
        "ike.dh_group",
    }


def test_adapter_marks_zero_responder_identity_not_testable(tmp_path: Path) -> None:
    """Do not project a reflected initiator packet as responder findings (#766)."""
    reflected = (_FIXTURES / "ike_scan_1_9_5_loopback_ikev2.txt").read_text()
    binary = _tool(
        tmp_path,
        f"""if "--version" in sys.argv:
    print("ike-scan 1.9.5")
    raise SystemExit
print({reflected!r})""",
    )

    result = IkeScanAdapter(binary).run(_source(), timeout_seconds=1)

    assert result.failure is None
    assert len(result.evidence) == 1
    assert result.evidence[0].evidence_type == "ike.mode.unbound"
    assert result.evidence[0].observation_type is ObservationType.NOT_TESTABLE
    assert result.evidence[0].failure_category is FailureCategory.IKE_OUTPUT_MALFORMED


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"source_port": -1}, "source_port"),
        ({"source_port": 65536}, "source_port"),
        ({"retry": 0}, "retry"),
        ({"output_limit": 0}, "output_limit"),
    ],
)
def test_adapter_rejects_invalid_limits(kwargs: dict[str, int], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        IkeScanAdapter(**kwargs)


def test_missing_adapter_reports_dependency_and_typed_failures() -> None:
    adapter = IkeScanAdapter("qureddy-definitely-missing-ike-scan")
    wrong = ScanSource(kind=SourceKind.STATIC_INVENTORY, locator="x", protocol="ike")

    assert not adapter.available()
    assert adapter.version == "unknown"
    assert adapter.dependency().failure_category is FailureCategory.LOCAL_IKE_SCAN_MISSING
    assert adapter.run(wrong, timeout_seconds=1).failure.kind is CollectionFailureKind.UNSUPPORTED
    assert (
        adapter.run(_source(), timeout_seconds=1).failure.kind is CollectionFailureKind.UNAVAILABLE
    )
    with pytest.raises(FileNotFoundError):
        adapter._require_binary()  # noqa: SLF001


@pytest.mark.parametrize(
    "source",
    [
        ScanSource(kind=SourceKind.ENDPOINT, protocol="ike", locator="ike://host:500"),
        _source(mode="invalid"),
        _source(locator="ike:missing-authority"),
    ],
)
def test_adapter_rejects_malformed_sources(tmp_path: Path, source: ScanSource) -> None:
    adapter = IkeScanAdapter(_tool(tmp_path, "raise SystemExit(0)"))
    result = adapter.run(source, timeout_seconds=1)
    assert result.failure.kind is CollectionFailureKind.MALFORMED


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ("raise SystemExit(7)", CollectionFailureKind.EXECUTION),
        ("print('0' * 5000, end='')", CollectionFailureKind.MALFORMED),
        ("import time; time.sleep(3)", CollectionFailureKind.TIMEOUT),
    ],
)
def test_adapter_maps_real_process_failures(
    tmp_path: Path, body: str, expected: CollectionFailureKind
) -> None:
    adapter = IkeScanAdapter(_tool(tmp_path, body), output_limit=64)
    result = adapter.run(_source(), timeout_seconds=1)
    assert result.failure.kind is expected
    assert result.evidence[0].observation_type is ObservationType.NOT_TESTABLE


def test_adapter_maps_exec_format_error(tmp_path: Path) -> None:
    suffix = ".exe" if os.name == "nt" else ""
    binary = tmp_path / f"bad-executable{suffix}"
    binary.write_text("not an executable format")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
    result = IkeScanAdapter(str(binary)).run(_source(), timeout_seconds=1)
    assert result.failure.kind is CollectionFailureKind.EXECUTION


def test_version_falls_back_for_empty_nonzero_and_unexecutable_tools(tmp_path: Path) -> None:
    empty = IkeScanAdapter(_tool(tmp_path, "raise SystemExit(0)"))
    assert empty.version == "unknown"
    assert IkeScanAdapter(_tool(tmp_path, "raise SystemExit(2)")).version == "unknown"


def test_process_state_helpers_cover_each_typed_outcome() -> None:
    outputs = [
        ProcessOutput(-9, b"", b"", 1, timed_out=True),
        ProcessOutput(-9, b"", b"", 1, output_limited=True),
        ProcessOutput(2, b"", b"", 1),
        ProcessOutput(0, b"Handshake returned", b"", 1),
    ]
    assert [_output_failure_category(item) for item in outputs] == [
        FailureCategory.IKE_PROBE_TIMEOUT,
        FailureCategory.IKE_OUTPUT_LIMIT,
        FailureCategory.LOCAL_IKE_SCAN_BROKEN,
        None,
    ]
    assert [
        _process_failure(item).kind if _process_failure(item) else None for item in outputs
    ] == [
        CollectionFailureKind.TIMEOUT,
        CollectionFailureKind.MALFORMED,
        CollectionFailureKind.EXECUTION,
        None,
    ]
    assert (
        _process_response(IKEMode.IKEV2, output=outputs[0], text="").status
        is IKEParseStatus.NO_RESPONSE
    )
    assert (
        _process_response(IKEMode.IKEV2, output=outputs[-1], text="Handshake returned").status
        is IKEParseStatus.RESPONDED
    )


def test_response_evidence_covers_rejection_silence_and_identity() -> None:
    rejected = ParsedIKEResponse(
        mode=IKEMode.IKEV2,
        status=IKEParseStatus.REJECTED,
        responder_notify="NO_PROPOSAL_CHOSEN",
    )
    rejected_records = _response_evidence(
        rejected, asset_id="asset-1", source="fixture", probe_result=_probe(), nat_t=True
    )
    assert [record.evidence_type for record in rejected_records] == [
        "ike.mode.rejected",
        "ike.notify",
    ]
    silent = ParsedIKEResponse(mode=IKEMode.IKEV1_MAIN, status=IKEParseStatus.NO_RESPONSE)
    assert (
        _response_evidence(
            silent, asset_id="asset-1", source="fixture", probe_result=_probe(), nat_t=False
        )[0].observation_type
        is ObservationType.NO_RESPONSE
    )
    identity = ParsedIKEResponse(
        mode=IKEMode.IKEV1_AGGRESSIVE,
        status=IKEParseStatus.RESPONDED,
        identity_exposed=True,
    )
    records = _response_evidence(
        identity, asset_id="asset-1", source="fixture", probe_result=_probe(), nat_t=False
    )
    assert records[-1].evidence_type == "ike.identity_exposed"
