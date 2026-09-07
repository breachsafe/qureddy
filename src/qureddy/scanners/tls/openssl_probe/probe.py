# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""TLS handshake probes executed through OpenSSL.

The probe owns process invocation and preserves the boundary between raw
evidence and parser input:

    probe arguments
    ├── ``-brief`` transcript from OpenSSL
    ├── stdout + stderr → ``parser_input`` → TLS negotiation parser
    └── raw stdout/stderr → hashes and bounded excerpts → ``ProbeResult``

The parser consumes the combined transcript because OpenSSL writes the
``-brief`` status lines to stderr on the supported 3.5.x baseline. Keeping
the raw streams separate preserves their independent integrity hashes.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from qureddy.scanners.tls._classify import classify_failure
from qureddy.scanners.tls.connection import StartTLSMode, build_s_client_args
from qureddy.scanners.tls.openssl_probe._constants import (
    CLASSICAL_GROUP,
    DEFAULT_TIMEOUT_SECONDS,
    HYBRID_GROUP,
)
from qureddy.scanners.tls.openssl_probe._logging import (
    log_subprocess_complete,
    log_subprocess_start,
)
from qureddy.scanners.tls.openssl_probe._results import (
    build_probe_result,
    combined_probe_output,
    result_from_timeout,
)
from qureddy.scanners.tls.openssl_probe.executor import raise_for_launch
from qureddy.scanners.tls.openssl_probe.executor import run_openssl as execute

if TYPE_CHECKING:
    from qureddy.core.models import ProbeResult


def run_group_probe(
    openssl_path: str,
    host: str,
    port: int,
    sni: str | None,
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    attempt_number: int = 1,
    group: str = HYBRID_GROUP,
    starttls: StartTLSMode | None = None,
) -> ProbeResult:
    """Probe the endpoint forcing one TLS 1.3 key-exchange group.

    Defaults to the primary hybrid readiness group for backward compatibility. Callers may
    force supplementary hybrid or pure-PQ groups through the same bounded OpenSSL path.
    """
    args = _build_probe_args(openssl_path, host, port, sni, group=group, starttls=starttls)
    return _run_probe(args, timeout_seconds=timeout_seconds, attempt_number=attempt_number)


# Public compatibility name retained from the original single-hybrid probe API.
run_hybrid_probe = run_group_probe


def run_classical_probe(
    openssl_path: str,
    host: str,
    port: int,
    sni: str | None,
    *,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    attempt_number: int = 1,
    starttls: StartTLSMode | None = None,
) -> ProbeResult:
    """Probe the endpoint with the classical fallback key-exchange group."""
    args = _build_probe_args(
        openssl_path, host, port, sni, group=CLASSICAL_GROUP, starttls=starttls
    )
    return _run_probe(args, timeout_seconds=timeout_seconds, attempt_number=attempt_number)


def _build_probe_args(
    openssl_path: str,
    host: str,
    port: int,
    sni: str | None,
    *,
    group: str,
    starttls: StartTLSMode | None = None,
) -> list[str]:
    return build_s_client_args(
        openssl_path,
        host,
        port,
        sni,
        # ``parse_brief_output`` parses the stable ``-brief`` labels. OpenSSL
        # writes this transcript to stderr; ``_run_probe`` combines both
        # streams for parsing while retaining each raw stream for evidence.
        extra=("-tls1_3", "-groups", group, "-brief"),
        starttls=starttls,
    )


def _run_probe(
    args: list[str],
    *,
    timeout_seconds: int,
    attempt_number: int,
) -> ProbeResult:
    started = datetime.now(UTC)
    log_subprocess_start(args, timeout_seconds, attempt_number)
    outcome = execute(args, timeout_seconds=timeout_seconds)
    if outcome.timed_out:
        return result_from_timeout(
            args, outcome.stdout, outcome.stderr, started, timeout_seconds, attempt_number
        )
    raise_for_launch(outcome, args[0])
    return_code = outcome.returncode
    assert return_code is not None  # noqa: S101 -- OK launch guarantees an exit code
    duration_ms = int((datetime.now(UTC) - started).total_seconds() * 1000)
    failure = classify_failure(outcome.stderr) if return_code else None
    log_subprocess_complete(
        args,
        return_code,
        duration_ms,
        attempt_number,
        failure,
        stdout=outcome.stdout,
        stderr=outcome.stderr,
    )
    parser_input = combined_probe_output(outcome.stdout, outcome.stderr)
    return build_probe_result(
        args=args,
        stdout=outcome.stdout,
        stderr=outcome.stderr,
        parser_input=parser_input,
        return_code=return_code,
        duration_ms=duration_ms,
        attempt_number=attempt_number,
        timeout_seconds=timeout_seconds,
        failure_category=failure,
    )
