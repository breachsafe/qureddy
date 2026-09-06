# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Bounded external-tool adapter for stock ``ike-scan``."""

from __future__ import annotations

import hashlib
import shutil
from functools import cached_property
from pathlib import Path
from urllib.parse import urlparse

from qureddy.core.contracts import (
    Capability,
    CollectionFailure,
    CollectionFailureKind,
    CollectionResult,
    ScanSource,
    SourceKind,
)
from qureddy.core.logging import get_logger
from qureddy.core.models import (
    ExternalToolDependency,
    FailureCategory,
    ProbeCommand,
    ProbeResult,
)
from qureddy.scanners.ike.evidence import response_evidence as _response_evidence
from qureddy.scanners.ike.execution import ProcessOutput, run_bounded
from qureddy.scanners.ike.parser import ParsedIKEResponse, parse_ike_scan_output
from qureddy.scanners.ike.psk import is_pskcrack_artifact, temporary_pskcrack_path
from qureddy.scanners.ike.types import IKEMode, IKEParseStatus

_LOG = get_logger(__name__)
_DEFAULT_OUTPUT_LIMIT = 256 * 1024
_DEFAULT_BACKOFF = 1.5
_MAX_PORT = 65535


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _decode(value: bytes) -> str:
    return value.decode("utf-8", errors="replace")


class IkeScanAdapter:
    """Single subprocess boundary for the optional ``ike-scan`` executable."""

    tool_id = "ike-scan"
    capabilities = frozenset({Capability.IKE_ENDPOINT})

    def __init__(
        self,
        binary_name: str = "ike-scan",
        *,
        source_port: int = 0,
        retry: int = 2,
        output_limit: int = _DEFAULT_OUTPUT_LIMIT,
    ) -> None:
        """Configure the executable, source port, retry count, and output bound."""
        if not 0 <= source_port <= _MAX_PORT:
            raise ValueError("source_port must be in range 0..65535")
        if retry < 1:
            raise ValueError("retry must be at least 1")
        if output_limit < 1:
            raise ValueError("output_limit must be at least 1")
        self._binary_name = binary_name
        self._source_port = source_port
        self._retry = retry
        self._output_limit = output_limit

    @cached_property
    def _binary(self) -> str | None:
        return shutil.which(self._binary_name)

    @cached_property
    def version(self) -> str:
        """Return the bounded, first-line tool version or ``unknown``."""
        if self._binary is None:
            return "unknown"
        try:
            output = run_bounded([self._binary, "--version"], timeout_seconds=5, output_limit=4096)
        except OSError:
            return "unknown"
        if output.return_code != 0 or output.timed_out or output.output_limited:
            return "unknown"
        version_stream = output.stdout or output.stderr
        first_line = _decode(version_stream).splitlines()
        return first_line[0].removeprefix("ike-scan ").strip() if first_line else "unknown"

    def available(self) -> bool:
        """Return whether the configured executable resolves on PATH."""
        return self._binary is not None

    def dependency(self) -> ExternalToolDependency:
        """Describe the exact external runtime used by this adapter."""
        failure = None if self.available() else FailureCategory.LOCAL_IKE_SCAN_MISSING
        return ExternalToolDependency(
            name=self.tool_id,
            path=self._binary,
            version=self.version if self.available() else None,
            failure_category=failure,
        )

    def run(self, source: ScanSource, *, timeout_seconds: int) -> CollectionResult:
        """Run one mode described in ``source.metadata`` and normalize its evidence."""
        if source.kind is not SourceKind.ENDPOINT or source.protocol != "ike":
            return self._failure(CollectionFailureKind.UNSUPPORTED, "source is not an IKE endpoint")
        if self._binary is None:
            return self._failure(CollectionFailureKind.UNAVAILABLE, "ike-scan is unavailable")
        try:
            mode = IKEMode(source.metadata["mode"])
            asset_id = source.metadata["asset_id"]
            nat_t = source.metadata.get("nat_t") == "true"
            parsed = urlparse(source.locator)
            host = parsed.hostname
            port = parsed.port
        except (KeyError, ValueError):  # fmt: skip  # pylint parser lacks Python 3.14 syntax
            return self._failure(CollectionFailureKind.MALFORMED, "invalid IKE source metadata")
        if host is None or port is None:
            return self._failure(CollectionFailureKind.MALFORMED, "IKE source has no endpoint")
        try:
            response, probe_result, output, psk_hash_exposed = self._invoke(
                mode, host=host, port=port, nat_t=nat_t, timeout=timeout_seconds
            )
        except OSError as exc:
            return self._failure(CollectionFailureKind.EXECUTION, str(exc))
        evidence = tuple(
            _response_evidence(
                response,
                asset_id=asset_id,
                source=self._source_name,
                probe_result=probe_result,
                nat_t=nat_t,
                psk_hash_exposed=psk_hash_exposed,
            )
        )
        failure = _process_failure(output)
        return CollectionResult(
            collector=self.tool_id,
            collector_version=self.version,
            evidence=evidence,
            failure=failure,
        )

    @property
    def _source_name(self) -> str:
        return f"ike-scan/{self.version}"

    def _invoke(
        self, mode: IKEMode, *, host: str, port: int, nat_t: bool, timeout: int
    ) -> tuple[ParsedIKEResponse, ProbeResult, ProcessOutput, bool]:
        """Execute and parse one bounded mode probe."""
        binary = self._require_binary()
        with temporary_pskcrack_path(enabled=mode is IKEMode.IKEV1_AGGRESSIVE) as psk_path:
            argv = self._argv(
                mode, host=host, port=port, nat_t=nat_t, timeout=timeout, psk_path=psk_path
            )
            output = run_bounded(argv, timeout_seconds=timeout + 2, output_limit=self._output_limit)
            psk_hash_exposed = psk_path is not None and is_pskcrack_artifact(psk_path)
        text = f"{_decode(output.stdout)}\n{_decode(output.stderr)}"
        command_args = tuple(
            "--pskcrack=<private-temp>" if arg.startswith("--pskcrack=") else arg
            for arg in argv[1:]
        )
        response = _process_response(mode, output=output, text=text)
        category = _output_failure_category(output, response=response)
        probe_result = ProbeResult(
            command=ProbeCommand(
                executable=binary,
                args=command_args,
                timeout_seconds=timeout + 2,
                redacted=psk_path is not None,
            ),
            return_code=output.return_code,
            stdout_sha256=_digest(output.stdout),
            stderr_sha256=_digest(output.stderr),
            parser_input=text,
            duration_ms=output.duration_ms,
            failure_category=category,
        )
        _LOG.debug(
            "ike_scan.completed",
            mode=mode.value,
            port=port,
            nat_t=nat_t,
            status=response.status.value,
            stdout_bytes=len(output.stdout),
            stderr_bytes=len(output.stderr),
            psk_hash_exposed=psk_hash_exposed,
        )
        return response, probe_result, output, psk_hash_exposed

    def _argv(
        self,
        mode: IKEMode,
        *,
        host: str,
        port: int,
        nat_t: bool,
        timeout: int,
        psk_path: Path | None = None,
    ) -> list[str]:
        """Build one list-form invocation with explicit transport settings."""
        binary = self._require_binary()
        retry_window = sum(_DEFAULT_BACKOFF**attempt for attempt in range(self._retry))
        initial_timeout_ms = max(100, int(timeout * 1000 / retry_window))
        argv = [
            binary,
            "--retry",
            str(self._retry),
            "--timeout",
            str(initial_timeout_ms),
            "--backoff",
            str(_DEFAULT_BACKOFF),
        ]
        if nat_t:
            argv.append("--nat-t")
        source_port = self._source_port or (4500 if nat_t else 500)
        argv.extend(("--sport", str(source_port), "--dport", str(port), "--multiline"))
        if mode is IKEMode.IKEV1_AGGRESSIVE:
            argv.append("--aggressive")
            if psk_path is not None:
                argv.append(f"--pskcrack={psk_path}")
        elif mode is IKEMode.IKEV2:
            argv.append("--ikev2")
        argv.append(host)
        return argv

    def _require_binary(self) -> str:
        """Return the resolved executable after the availability guard."""
        if self._binary is None:
            raise FileNotFoundError(self._binary_name)
        return self._binary

    def _failure(self, kind: CollectionFailureKind, message: str) -> CollectionResult:
        """Return one typed collector failure with adapter provenance."""
        return CollectionResult(
            collector=self.tool_id,
            collector_version=self.version,
            failure=CollectionFailure(kind=kind, message=message),
        )


def _output_failure_category(
    output: ProcessOutput, *, response: ParsedIKEResponse | None = None
) -> FailureCategory | None:
    """Map bounded process state onto the stable scan failure vocabulary."""
    if output.timed_out:
        return FailureCategory.IKE_PROBE_TIMEOUT
    if output.output_limited:
        return FailureCategory.IKE_OUTPUT_LIMIT
    if output.return_code != 0:
        return FailureCategory.LOCAL_IKE_SCAN_BROKEN
    if response is not None and response.status is IKEParseStatus.UNBOUND:
        return FailureCategory.IKE_OUTPUT_MALFORMED
    return None


def _process_response(mode: IKEMode, *, output: ProcessOutput, text: str) -> ParsedIKEResponse:
    """Keep process failures distinct from parsed responder states."""
    if output.timed_out or output.output_limited or output.return_code != 0:
        return ParsedIKEResponse(mode=mode, status=IKEParseStatus.NO_RESPONSE)
    return parse_ike_scan_output(mode, text=text)


def _process_failure(output: ProcessOutput) -> CollectionFailure | None:
    """Map child-process failures onto the collector contract."""
    if output.timed_out:
        return CollectionFailure(kind=CollectionFailureKind.TIMEOUT, message="probe timeout")
    if output.output_limited:
        return CollectionFailure(
            kind=CollectionFailureKind.MALFORMED,
            message="tool output exceeded the configured byte limit",
        )
    if output.return_code != 0:
        return CollectionFailure(
            kind=CollectionFailureKind.EXECUTION,
            message="ike-scan exited nonzero",
        )
    return None
