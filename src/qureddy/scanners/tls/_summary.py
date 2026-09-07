# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Scan-level summary rollup helpers.

Pure functions that fold a list of `Finding` and `Evidence` records into
a `ScanSummary`. Extracted from `scanner.py` to keep that file under the
400-line hard ceiling.
"""

from __future__ import annotations

from qureddy.core.models import (
    LOCAL_CAPABILITY_CATEGORIES,
    Evidence,
    FailureCategory,
    Finding,
    ScanSummary,
    ScanTarget,
)

# Readiness/severity rollup now lives in the shared protocol-agnostic core (#248).
# Re-exported here (listed in __all__) so existing TLS callers and tests keep importing
# it from _summary, and mypy treats the re-export as intentional rather than incidental.
from qureddy.scanners.common.posture import build_scan_summary
from qureddy.scanners.common.rollup import highest_severity, scan_readiness

__all__ = ["build_summary", "highest_severity", "scan_readiness", "summary_failure_category"]


def build_summary(
    target: ScanTarget,
    findings: list[Finding],
    evidence: list[Evidence],
) -> ScanSummary:
    """Build the top-level `ScanSummary` from the scan's findings + evidence."""
    failure_category = summary_failure_category(findings, evidence)
    return build_scan_summary(
        target,
        findings,
        evidence,
        failure_category,
        protocol="tls",
    )


# Issue #241: retry attempts accumulate rather than replace, so an earlier
# failed attempt's Finding survives in the list alongside a later attempt's
# success. A failure category must not outlive proof that the probe it
# describes eventually succeeded. The classical control result is deliberately
# excluded: it is a separate diagnostic probe and cannot clear hybrid failure
# (#836).
_SUCCESS_RULE_IDS: frozenset[str] = frozenset(
    {
        "tls.hybrid.negotiated_pq",  # #330: renamed from ...negotiated_x25519mlkem768 (structural)
        "tls.pq.negotiated_pure",  # #330: a pure-PQ negotiation is also a reached-server success
    }
)


def summary_failure_category(
    findings: list[Finding],
    evidence: list[Evidence],
) -> FailureCategory | None:
    """Surface the exact `FailureCategory` from supporting evidence.

    Local-capability failures take precedence over target-side probe
    failures so consumers can distinguish "your openssl is broken" from
    "the server isn't reachable". Within each tier, the first matching
    evidence record wins.

    A successful negotiation finding (e.g. from a later retry attempt)
    supersedes an earlier attempt's failure category — see #241.
    """
    evidence_by_id = {e.id: e for e in evidence}
    local_match = _first_matching_category(
        findings,
        evidence_by_id,
        "tls.hybrid.not_testable",
        allowed=LOCAL_CAPABILITY_CATEGORIES,
    )
    if local_match is not None:
        return local_match
    if any(f.rule_id in _SUCCESS_RULE_IDS for f in findings):
        return None
    return _first_matching_category(
        findings,
        evidence_by_id,
        "tls.hybrid.probe_failed",
        allowed=None,
    )


def _first_matching_category(
    findings: list[Finding],
    evidence_by_id: dict[str, Evidence],
    rule_id: str,
    *,
    allowed: frozenset[FailureCategory] | None,
) -> FailureCategory | None:
    """Find the first finding for `rule_id` and return its evidence's category."""
    for finding in findings:
        if finding.rule_id != rule_id:
            continue
        for ev_id in finding.evidence_ids:
            ev = evidence_by_id.get(ev_id)
            if ev is None or ev.failure_category is None:
                continue
            if allowed is None or ev.failure_category in allowed:
                return ev.failure_category
    return None
