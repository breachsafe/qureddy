# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Pure precondition decision for the opt-in IKE acceptance suite.

Separated from the suite itself so it can be unit tested in the hermetic lane.
Every CI lane passes ``--ignore=tests/ike_lab``, so logic that lives only in
``test_live_ike.py`` is never executed by a gate and can break silently.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterable

    from qureddy.core.models import Evidence

_MODE_PREFIX = "ike.mode."
_RESPONDED = "ike.mode.responded"
# A responder that explicitly rejects the proposal still proves the lab is up.
# ``unbound`` is the loopback self-reflection an unbound UDP/500 produces, and
# ``no_response`` is silence; neither proves a responder exists (#740).
_ANSWERED = frozenset({_RESPONDED, "ike.mode.rejected"})


class LabOutcome(StrEnum):
    """What the suite should do about the observed lab state."""

    RUN = "run"
    SKIP = "skip"
    FAIL = "fail"


@dataclass(frozen=True, slots=True)
class LabVerdict:
    """One precondition decision with the reason a reader needs."""

    outcome: LabOutcome
    reason: str


def evaluate_lab(evidence: Iterable[Evidence], *, status: str, target: str) -> LabVerdict:
    """Decide whether the authorized responder is present, absent, or broken.

    A completed handshake runs the suite. An explicit rejection means the lab is
    reachable but misconfigured, which is a failure the operator must see rather
    than a skipped suite. Anything else is an absent lab and skips.
    """
    types = {
        record.evidence_type for record in evidence if record.evidence_type.startswith(_MODE_PREFIX)
    }
    if _RESPONDED in types:
        return LabVerdict(LabOutcome.RUN, "authorized responder completed a handshake")
    if types & _ANSWERED:
        return LabVerdict(
            LabOutcome.FAIL,
            f"IKE responder at {target} answered but no mode completed a handshake "
            f"(scan status {status}); the lab is reachable and misconfigured",
        )
    return LabVerdict(
        LabOutcome.SKIP,
        f"no authorized IKE responder answered {target}:500 (scan status {status}); "
        "start the lab responder to run this suite",
    )
