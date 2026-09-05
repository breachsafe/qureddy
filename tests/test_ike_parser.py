# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Parser regressions for stock ``ike-scan --multiline`` output."""

from __future__ import annotations

from pathlib import Path

import pytest

from qureddy.scanners.ike.parser import parse_ike_scan_output
from qureddy.scanners.ike.types import IKEMode, IKEParseStatus

_FIXTURES = Path(__file__).parent / "fixtures" / "ike"


def test_key_exchange_size_never_infers_a_group() -> None:
    """Cover the MODP/ECP payload-size collision from issue #679."""
    response = parse_ike_scan_output(
        IKEMode.IKEV2,
        text="vpn\tIKEv2 SA_INIT Handshake returned\n\tKeyExchange(96 bytes)",
    )

    assert response.dh_groups == ()


def test_identity_requires_every_aggressive_mode_marker() -> None:
    """Reject incomplete pre-authentication identity evidence from issue #680."""
    incomplete = "Handshake returned\nKeyExchange(128 bytes)\nID(Type=ID_USER_FQDN)"

    assert not parse_ike_scan_output(IKEMode.IKEV1_AGGRESSIVE, text=incomplete).identity_exposed


def test_explicit_notify_is_distinct_from_silence() -> None:
    """Preserve the named rejection required by issue #686."""
    notify = (
        "vpn\tNotify message 14 (NO-PROPOSAL-CHOSEN)\n"
        "Ending ike-scan: 0 returned handshake; 1 returned notify"
    )
    silent = "Ending ike-scan: 0 returned handshake; 0 returned notify"

    rejected = parse_ike_scan_output(IKEMode.IKEV2, text=notify)
    no_response = parse_ike_scan_output(IKEMode.IKEV2, text=silent)

    assert rejected.status is IKEParseStatus.REJECTED
    assert rejected.responder_notify == "NO-PROPOSAL-CHOSEN"
    assert no_response.status is IKEParseStatus.NO_RESPONSE


def test_ikev2_underscore_notify_is_an_explicit_rejection() -> None:
    """Preserve ike-scan's IKEv2 registry spelling from issue #715."""
    output = (
        "vpn\tNotify message 14 (NO_PROPOSAL_CHOSEN)\n"
        "Ending ike-scan: 0 returned handshake; 1 returned notify"
    )

    response = parse_ike_scan_output(IKEMode.IKEV2, text=output)

    assert response.status is IKEParseStatus.REJECTED
    assert response.responder_notify == "NO_PROPOSAL_CHOSEN"


def test_named_stateless_error_precedes_zero_spi_binding_failure() -> None:
    """Preserve an explicit IKEv2 error whose responder SPI is allowed to be zero."""
    output = (
        "vpn\tNotify message 14 (NO_PROPOSAL_CHOSEN)\n"
        "\tHDR=(CKY-R=0000000000000000, IKEv2, flags=0x20)\n"
        "Ending ike-scan: 0 returned handshake; 1 returned notify"
    )

    response = parse_ike_scan_output(IKEMode.IKEV2, text=output)

    assert response.status is IKEParseStatus.REJECTED
    assert response.responder_notify == "NO_PROPOSAL_CHOSEN"


def test_ikev2_request_flag_cannot_prove_a_response() -> None:
    """Require RFC 7296's response bit before accepting IKEv2 tool output."""
    output = (
        "vpn\tIKEv2 SA_INIT Handshake returned\n\tHDR=(CKY-R=1234567890abcdef, IKEv2, flags=0x08)"
    )

    response = parse_ike_scan_output(IKEMode.IKEV2, text=output)

    assert response.status is IKEParseStatus.UNBOUND
    bound = output.replace("flags=0x08", "flags=0x20")
    assert parse_ike_scan_output(IKEMode.IKEV2, text=bound).status is IKEParseStatus.RESPONDED


def test_zero_ikev2_responder_spi_is_unbound() -> None:
    """Reject an IKEv2 response with an unbound responder SPI."""
    output = "vpn\tIKEv2 SA_INIT Handshake returned\n\tHDR=(SPIr=0000000000000000, flags=0x20)"

    response = parse_ike_scan_output(IKEMode.IKEV2, text=output)

    assert response.status is IKEParseStatus.UNBOUND


@pytest.mark.parametrize(
    ("mode", "fixture_name"),
    [
        (IKEMode.IKEV1_MAIN, "ike_scan_1_9_5_loopback_main.txt"),
        (IKEMode.IKEV1_AGGRESSIVE, "ike_scan_1_9_5_loopback_aggressive.txt"),
        (IKEMode.IKEV2, "ike_scan_1_9_5_loopback_ikev2.txt"),
    ],
)
def test_zero_responder_identity_cannot_prove_a_handshake(mode: IKEMode, fixture_name: str) -> None:
    """Reject ike-scan 1.9.5 loopback self-reflection as unbound evidence (#766)."""
    text = (_FIXTURES / fixture_name).read_text()

    response = parse_ike_scan_output(mode, text=text)

    assert response.status.value == "unbound"
    assert response.encryption == ()
    assert response.prf == ()
    assert response.integrity == ()
    assert response.dh_groups == ()
    assert not response.identity_exposed
