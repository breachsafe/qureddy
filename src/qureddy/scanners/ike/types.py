# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Fixed internal vocabulary for the ``ike-scan`` adapter."""

from __future__ import annotations

from enum import StrEnum


class IKEMode(StrEnum):
    """Exchange modes supported by stock ``ike-scan``."""

    IKEV1_MAIN = "ikev1_main"
    IKEV1_AGGRESSIVE = "ikev1_aggressive"
    IKEV2 = "ikev2"


class IKEParseStatus(StrEnum):
    """Non-overlapping responder states parsed from completed tool output."""

    RESPONDED = "responded"
    REJECTED = "rejected"
    UNBOUND = "unbound"
    NO_RESPONSE = "no_response"
