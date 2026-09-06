# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""The ``qureddy scan ike`` command body."""

from __future__ import annotations

import typer

from qureddy._branding import PROJECT_URL
from qureddy.cli._environment import block_internal_targets
from qureddy.cli._errors import EXIT_OK, EXIT_USAGE, _fail
from qureddy.cli._execute import _execute_scan
from qureddy.cli._help import _NO_WRAP_CONTEXT_SETTINGS, _OUTPUT_HELP_SECTION, _colorize_help_text
from qureddy.cli._options import (
    CompactOpt,
    DeprecatedReproducibleOpt,
    DeterministicOpt,
    FormatOpt,
    IkeScanOpt,
    IkeTargetArg,
    JsonLogsOpt,
    MinSeverityOpt,
    NatTOpt,
    OutputDirOpt,
    OutputOpt,
    QuietOpt,
    SourcePortOpt,
    TimeoutOpt,
    VerboseOpt,
)
from qureddy.cli._render import _open_output_file, _prepare_output_dir, _render
from qureddy.cli.main import scan_app
from qureddy.core.contracts import ScanSource, SourceKind
from qureddy.core.errors import TargetParseError
from qureddy.core.logging import start_run_logging
from qureddy.core.models import OutputFormat, ScanTarget
from qureddy.core.registry import CollectorRegistry
from qureddy.core.targets import parse_ike_target
from qureddy.scanners.ike import IkeScanAdapter, IKEScanner

_SCAN_IKE_EPILOG = _colorize_help_text(f"""\
EXAMPLES:

\b
qureddy scan ike vpn.example.com
qureddy scan ike vpn.example.com --nat-t
qureddy scan ike 192.0.2.10 --source-port 500 --format json

TRUST BOUNDARY:

\b
Stock ike-scan supplies lower-trust discovery evidence. Its IKEv2 sender is
experimental and sends one default proposal. QuReddy reports transform identifiers,
Historic IKEv1, weak algorithms, explicit NOTIFY responses, and Aggressive Mode exposure.
It does not claim final negotiation, RFC 9370 additional-key-exchange completion,
favorable post-quantum readiness, or HNDL protection from this backend.

{_OUTPUT_HELP_SECTION}

EXIT CODES:

\b
0   scan completed, including silence or explicit rejection with unknown posture
2   target probe timed out or returned malformed output
3   ike-scan is missing or unusable
4   usage / configuration error

Project: {PROJECT_URL}
""")


def _parse_ike_scan_target(target: str) -> ScanTarget:
    """Parse one CLI target and convert validation errors to usage exits."""
    try:
        return parse_ike_target(target, block_internal=block_internal_targets())
    except TargetParseError as exc:
        _fail(f"invalid target: {exc}", EXIT_USAGE)


def _select_ike_scanner(
    target: ScanTarget, *, binary_name: str, source_port: int, nat_t: bool
) -> IKEScanner:
    """Select the configured IKE scanner through the canonical registry."""
    scanner = IKEScanner(
        IkeScanAdapter(binary_name, source_port=source_port),
        nat_t=nat_t,
    )
    selected = CollectorRegistry([scanner]).select_scanner(
        ScanSource(kind=SourceKind.ENDPOINT, protocol="ike", locator=target.locator)
    )
    if not isinstance(selected, IKEScanner):  # pragma: no cover - registry invariant
        raise TypeError("IKE registry returned an incompatible scanner")
    return selected


@scan_app.command("ike", epilog=_SCAN_IKE_EPILOG, context_settings=_NO_WRAP_CONTEXT_SETTINGS)
def scan_ike_cmd(
    target: IkeTargetArg,
    fmt: FormatOpt = OutputFormat.RICH,
    output: OutputOpt = None,
    output_dir: OutputDirOpt = None,
    compact: CompactOpt = False,
    min_severity: MinSeverityOpt = None,
    timeout: TimeoutOpt = 8,
    ike_scan: IkeScanOpt = "ike-scan",
    nat_t: NatTOpt = False,
    source_port: SourcePortOpt = 0,
    verbose: VerboseOpt = 0,
    json_logs: JsonLogsOpt = False,
    quiet: QuietOpt = False,
    deterministic: DeterministicOpt = False,
    reproducible: DeprecatedReproducibleOpt = False,
) -> None:
    """Scan an IKE endpoint with the optional stock ike-scan executable."""
    machine_format = output_dir is not None or fmt is not OutputFormat.RICH
    effective_quiet = quiet or (machine_format and verbose == 0)
    start_run_logging(verbosity=verbose, json_logs=json_logs, quiet=effective_quiet, log=None)
    scan_target = _parse_ike_scan_target(target)
    _prepare_output_dir(output_dir, output)
    output_stream = _open_output_file(output)
    try:
        scanner = _select_ike_scanner(
            scan_target, binary_name=ike_scan, source_port=source_port, nat_t=nat_t
        )
        result, exit_code = _execute_scan(
            scanner, scan_target, timeout, machine_format=machine_format
        )
        _render(
            result,
            fmt,
            verbose,
            reproducible=deterministic or reproducible,
            compact=compact,
            min_severity=min_severity,
            stream=output_stream,
            output_dir=output_dir,
        )
        if exit_code != EXIT_OK:
            raise typer.Exit(code=exit_code)
    finally:
        if output_stream is not None:
            output_stream.close()
