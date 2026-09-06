# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""The `qureddy scan tls` command body and orchestration.

The TLS scanner has a dedicated public entry point alongside `cli/ssh.py`.
"""

from __future__ import annotations

from pathlib import Path
from typing import IO, TextIO

import structlog
import typer

from qureddy._branding import PROJECT_URL
from qureddy.cli._environment import block_internal_targets
from qureddy.cli._errors import (
    EXIT_INTERNAL_ERROR,
    EXIT_LOCAL_DEPENDENCY,
    EXIT_OK,
    EXIT_TARGET_FAILED,
    EXIT_USAGE,
    _echo_operator_diagnostic,
    _fail,
)
from qureddy.cli._execute import _execute_scan
from qureddy.cli._help import (
    _NO_WRAP_CONTEXT_SETTINGS,
    _OUTPUT_HELP_SECTION,
    _colorize_help_text,
)
from qureddy.cli._options import (
    CompactOpt,
    DeprecatedReproducibleOpt,
    DeterministicOpt,
    FormatOpt,
    JsonLogsOpt,
    LogOpt,
    MinSeverityOpt,
    OpenSSLOpt,
    OutputDirOpt,
    OutputOpt,
    QuietOpt,
    RetriesOpt,
    RetryDelayOpt,
    RetryOnOpt,
    SniOpt,
    StartTLSOpt,
    TargetArg,
    TimeoutOpt,
    VerboseOpt,
)
from qureddy.cli._render import _open_output_file, _prepare_output_dir, _render
from qureddy.cli.main import scan_app
from qureddy.collectors import NativeTLSCollector
from qureddy.core.contracts import ScanCollector, ScanSource, SourceKind
from qureddy.core.errors import CbomError, RetryConfigError, TargetParseError
from qureddy.core.logging import start_run_logging
from qureddy.core.models import FailureCategory, OutputFormat, ScanResult, ScanTarget, Severity
from qureddy.core.registry import CollectorRegistry
from qureddy.core.retry import parse_retry_on, validate_retry_args
from qureddy.core.targets import parse_target
from qureddy.scanners.tls.connection import StartTLSMode
from qureddy.scanners.tls.openssl_probe import DEFAULT_TIMEOUT_SECONDS
from qureddy.scanners.tls.scanner import (
    RetryConfig,
    TLSScanner,
)

# Tier-2 epilog for `qureddy scan tls --help` (issue #41 / ADR 0003 patterns 3-4).
#
# Exit-code lines reference the EXIT_* constants so a contract change there
# (e.g. issue #12's exit 70) doesn't drift the help text — single source of
# truth per agent-antipatterns "Copy-paste duplication" rule.
#
# Why every paragraph starts with `\b\n`:
#   Click's text formatter collapses single `\n` into spaces within a
#   paragraph (issue #71). The `\b` marker (literal backspace, ASCII 8)
#   tells the formatter to preserve literal newlines for THAT paragraph.
#   Each paragraph (each EXAMPLES pair, each EXIT CODES table, each
#   ENVIRONMENT row) needs its own `\b\n` prefix because blank lines
#   between paragraphs end the `\b` block. Single `\b` at the top of a
#   block isn't enough — paragraphs after the first blank reflow again.
_SCAN_TLS_EPILOG = _colorize_help_text(f"""\
EXAMPLES:

\b
# Most common: scan a hostname with rich console output.
qureddy scan tls google.com

\b
# Machine-readable JSON for CI pipelines.
qureddy scan tls pq.cloudflareresearch.com --format json

\b
# Correlated JSON and CBOM from one network scan.
qureddy scan tls pq.cloudflareresearch.com --output-dir run/

\b
# Scan an IP target with an SNI override for a name-based virtual host.
qureddy scan tls 1.1.1.1:443 --sni one.one.one.one

\b
# Tolerate transient network hiccups (3 retries, 2s apart).
qureddy scan tls flaky.example.com --retry-on tls_handshake_failed --retries 3 --retry-delay 2

\b
# Compact JSON written straight to a file (stdout stays empty and clean).
qureddy scan tls example.com --format json --compact --output scan.json

\b
# Human report trimmed to medium-and-above findings (machine formats stay complete).
qureddy scan tls example.com --min-severity medium

{_OUTPUT_HELP_SECTION}

SCAN BEHAVIOR:

\b
A full scan runs separate probes for TLS 1.3 hybrid and pure post-quantum key
exchange, a TLS 1.3 classical control, legacy TLS protocols, and certificate evidence. The
`--timeout` value applies to each probe, so total wall time can be several
times the timeout. Use `-vv` to see every subprocess start and completion;
`-vvv` also adds the exact commands to Rich output.

\b
For a faster diagnostic run, lower the per-probe timeout:
qureddy scan tls example.com --timeout 5 -vvv

EXIT CODES:

\b
{EXIT_OK}   scan succeeded
{EXIT_TARGET_FAILED}   target scan failed (handshake, parse, etc.)
{EXIT_LOCAL_DEPENDENCY}   local dependency missing or unsupported (requires OpenSSL 3.5.x LTS)
{EXIT_USAGE}   usage / configuration error
{EXIT_INTERNAL_ERROR}  internal qureddy error (BSD sysexits.h EX_SOFTWARE)

ENVIRONMENT:

\b
NO_COLOR         Disable ANSI color (https://no-color.org).

\b
QUREDDY_OPENSSL_PQC_BIN
                 Override the primary OpenSSL 3.5.x LTS binary
                 (precedence: --openssl > $QUREDDY_OPENSSL_PQC_BIN >
                 $QUREDDY_OPENSSL > $PATH).
QUREDDY_OPENSSL_WEAK_CIPHERS_BIN
                 Override the OpenSSL 1.0.2u weak-cipher binary
                 (legacy alias: $QUREDDY_LEGACY_OPENSSL).

Project: {PROJECT_URL}
""")


def _open_run_log(
    *, log: Path | None, machine_format: bool, verbose: int, json_logs: bool, quiet: bool
) -> TextIO | None:
    """Configure logging for one scan run; return the log-file stream (caller closes it).

    With ``--log`` set, machine-format auto-quiet does not apply and the level is floored at
    INFO so a clean run still records its story (otherwise a successful machine-format scan
    writes an empty WARNING-level log). The log file is an explicit diagnostic destination,
    so ``--quiet`` does not suppress its INFO records. A ``--log`` path that cannot be opened
    is a usage error (exit 4), reported before any scan work.
    """
    if log is not None:
        effective_quiet = False
        log_verbosity = max(verbose, 1)
    else:
        # JSON/CBOM stdout is a single machine-parsed document. The #15 fd-snapshot
        # fix only guards in-process stream rebinding (CliRunner, etc.); it cannot
        # protect real shell `2>&1` (the OS merged fd 1/2 before Python started —
        # #194), so a WARNING+ log line would corrupt that document for any real
        # `| jq` consumer. Default to quiet in these formats so the common case is
        # safe; an explicit -v/-vv/-vvv still wins (the user then accepts they must
        # keep stdout/stderr genuinely separate, not `2>&1`, to keep clean JSON).
        effective_quiet = quiet or (machine_format and verbose == 0)
        log_verbosity = verbose
    try:
        return start_run_logging(
            verbosity=log_verbosity, json_logs=json_logs, quiet=effective_quiet, log=log
        )
    except OSError as exc:
        _fail(f"cannot write --log file {log}: {exc.strerror or exc}", EXIT_USAGE)


@scan_app.command(
    "tls",
    epilog=_SCAN_TLS_EPILOG,
    # Issue #266: reuses the same _NO_WRAP_CONTEXT_SETTINGS as `app`/
    # `scan_app` instead of a separately-typed {"max_content_width": ...}
    # dict — one shared constant for "-h works + epilogs don't get
    # mangled" everywhere, so a future change can't add -h at one level
    # and silently miss another.
    context_settings=_NO_WRAP_CONTEXT_SETTINGS,
)
def scan_tls(
    target: TargetArg,
    sni: SniOpt = None,
    starttls: StartTLSOpt = None,
    openssl: OpenSSLOpt = None,
    output_format: FormatOpt = OutputFormat.RICH,
    output: OutputOpt = None,
    output_dir: OutputDirOpt = None,
    compact: CompactOpt = False,
    min_severity: MinSeverityOpt = None,
    timeout: TimeoutOpt = DEFAULT_TIMEOUT_SECONDS,
    retry_on: RetryOnOpt = None,
    retries: RetriesOpt = 0,
    retry_delay: RetryDelayOpt = 1.0,
    verbose: VerboseOpt = 0,
    json_logs: JsonLogsOpt = False,
    quiet: QuietOpt = False,
    log: LogOpt = None,
    deterministic: DeterministicOpt = False,
    reproducible: DeprecatedReproducibleOpt = False,
) -> None:
    """Scan a TLS endpoint for post-quantum readiness."""
    log_stream = _open_run_log(
        log=log,
        machine_format=_is_machine_format(output_dir, output_format),
        verbose=verbose,
        json_logs=json_logs,
        quiet=quiet,
    )
    try:
        exit_code = _scan_and_render(
            target=target,
            sni=sni,
            starttls=starttls,
            openssl=openssl,
            output_format=output_format,
            output=output,
            output_dir=output_dir,
            compact=compact,
            min_severity=min_severity,
            timeout=timeout,
            retry_on=retry_on,
            retries=retries,
            retry_delay=retry_delay,
            verbose=verbose,
            reproducible=deterministic or reproducible,
        )
        raise typer.Exit(code=exit_code)
    finally:
        _finish_run(log_stream)


def _scan_and_render(
    *,
    target: str,
    sni: str | None,
    starttls: StartTLSMode | None,
    openssl: str | None,
    output_format: OutputFormat,
    output: Path | None,
    output_dir: Path | None,
    compact: bool,
    min_severity: Severity | None,
    timeout: int,
    retry_on: str | None,
    retries: int,
    retry_delay: float,
    verbose: int,
    reproducible: bool,
) -> int:
    machine_format = _is_machine_format(output_dir, output_format)
    _prepare_output_dir(output_dir, output)
    output_stream: IO[str] | None = _open_output_file(output)
    try:
        retry_set = _parse_retry_args(retry_on, retries, retry_delay)
        scan_target = _parse_cli_target(target, sni)
        structlog.contextvars.bind_contextvars(target=scan_target.locator)
        scanner = _build_tls_scanner(openssl, retries, retry_delay, retry_set, starttls)
        result, exit_code = _execute_scan(
            _select_tls_scanner(scanner, scan_target),
            scan_target,
            timeout,
            machine_format=machine_format,
        )
        if not _render_result(
            result,
            output_format,
            verbose,
            reproducible=reproducible,
            compact=compact,
            min_severity=min_severity,
            stream=output_stream,
            output_dir=output_dir,
            machine_format=machine_format,
        ):
            return EXIT_INTERNAL_ERROR
        return exit_code
    finally:
        _close_output_stream(output_stream)


def _is_machine_format(output_dir: Path | None, output_format: OutputFormat) -> bool:
    """Return whether stdout must remain free of human-readable diagnostics."""
    return output_dir is not None or output_format in (
        OutputFormat.JSON,
        OutputFormat.CBOM,
        OutputFormat.JSONL,
    )


def _render_result(
    result: ScanResult,
    output_format: OutputFormat,
    verbose: int,
    *,
    reproducible: bool,
    compact: bool,
    min_severity: Severity | None,
    stream: IO[str] | None,
    output_dir: Path | None,
    machine_format: bool,
) -> bool:
    """Render one result and convert renderer failures to an operator diagnostic."""
    try:
        _render(
            result,
            output_format,
            verbose,
            reproducible=reproducible,
            compact=compact,
            min_severity=min_severity,
            stream=stream,
            output_dir=output_dir,
        )
    except CbomError as exc:
        _echo_operator_diagnostic(
            f"internal error rendering output: {exc}", machine_format=machine_format
        )
        return False
    return True


def _build_tls_scanner(
    openssl: str | None,
    retries: int,
    retry_delay: float,
    retry_set: frozenset[FailureCategory],
    starttls: StartTLSMode | None = None,
) -> TLSScanner:
    """Build the configured native scanner before registry selection."""
    return TLSScanner(
        openssl_path=openssl,
        retry=RetryConfig(retries=retries, retry_delay=retry_delay, retry_on=retry_set),
        starttls=starttls,
    )


def _select_tls_scanner(scanner: TLSScanner, target: ScanTarget) -> ScanCollector:
    """Select the native TLS collector through the protocol registry."""
    return CollectorRegistry([NativeTLSCollector(scanner)]).select_scanner(
        ScanSource(kind=SourceKind.ENDPOINT, protocol="tls", locator=target.locator)
    )


def _close_output_stream(stream: IO[str] | None) -> None:
    """Close an optional output stream owned by the scan command."""
    if stream is not None:
        stream.close()


def _finish_run(log_stream: TextIO | None) -> None:
    """Clear per-run context and close the owned diagnostic stream."""
    structlog.contextvars.clear_contextvars()
    _close_output_stream(log_stream)


def _parse_retry_args(
    retry_on: str | None,
    retries: int,
    retry_delay: float,
) -> frozenset[FailureCategory]:
    """Parse + validate retry CLI args; exit 4 on bad input."""
    try:
        retry_set = parse_retry_on(retry_on)
        validate_retry_args(retries=retries, retry_delay=retry_delay, retry_on=retry_set)
    except RetryConfigError as exc:
        _fail(str(exc), EXIT_USAGE)
    return retry_set


def _parse_cli_target(target: str, sni: str | None) -> ScanTarget:
    """Parse the positional target arg; exit 4 on a malformed target."""
    try:
        return parse_target(target, sni_override=sni, block_internal=block_internal_targets())
    except TargetParseError as exc:
        _fail(f"invalid target: {exc}", EXIT_USAGE)
