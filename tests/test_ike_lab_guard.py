# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Hermetic tests for the IKE lab precondition decision (#740).

The suite these guard lives for is excluded from every CI lane
(``--ignore=tests/ike_lab``), so without this file a wrong guard would skip the
acceptance suite forever and no gate would notice.
"""

from __future__ import annotations

import pytest

from qureddy.core.ids import new_id
from qureddy.core.models import Confidence, Evidence, ObservationType
from tests.ike_lab._guard import LabOutcome, evaluate_lab


def _mode_evidence(status: str) -> Evidence:
    """Build one mode-level record exactly as the adapter names it."""
    return Evidence(
        id=new_id("ev"),
        asset_id="asset-1",
        evidence_type=f"ike.mode.{status}",
        observation_type=ObservationType.OBSERVED,
        source="qureddy.scanners.ike.adapter",
        protocol="ike",
        confidence=Confidence.LOW,
    )


def test_completed_handshake_runs_the_suite() -> None:
    verdict = evaluate_lab([_mode_evidence("responded")], status="completed", target="127.0.0.1")

    assert verdict.outcome is LabOutcome.RUN


@pytest.mark.parametrize("status", ["unbound", "no_response"])
def test_absent_responder_skips(status: str) -> None:
    """Loopback self-reflection and silence both mean no lab is running."""
    verdict = evaluate_lab(
        [_mode_evidence(status)], status="ike_output_malformed", target="127.0.0.1"
    )

    assert verdict.outcome is LabOutcome.SKIP
    assert "no authorized IKE responder" in verdict.reason


def test_no_evidence_at_all_skips() -> None:
    verdict = evaluate_lab([], status="target_connect_failed", target="127.0.0.1")

    assert verdict.outcome is LabOutcome.SKIP


def test_explicit_rejection_fails_rather_than_skipping() -> None:
    """A reachable but misconfigured lab must be visible, not silently skipped."""
    verdict = evaluate_lab([_mode_evidence("rejected")], status="completed", target="127.0.0.1")

    assert verdict.outcome is LabOutcome.FAIL
    assert "reachable and misconfigured" in verdict.reason


def test_one_completed_mode_outranks_a_rejected_mode() -> None:
    verdict = evaluate_lab(
        [_mode_evidence("rejected"), _mode_evidence("responded")],
        status="completed",
        target="127.0.0.1",
    )

    assert verdict.outcome is LabOutcome.RUN


def test_non_mode_evidence_is_ignored() -> None:
    """Only mode-level records decide the precondition."""
    unrelated = Evidence(
        id=new_id("ev"),
        asset_id="asset-1",
        evidence_type="ike.notify",
        observation_type=ObservationType.OBSERVED,
        source="qureddy.scanners.ike.adapter",
        protocol="ike",
        confidence=Confidence.LOW,
    )

    verdict = evaluate_lab([unrelated], status="completed", target="127.0.0.1")

    assert verdict.outcome is LabOutcome.SKIP
