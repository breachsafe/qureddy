# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Parse bounded ``ike-scan --multiline`` output into typed observations."""

from __future__ import annotations

import re
from dataclasses import dataclass

from qureddy.scanners.ike.types import IKEMode, IKEParseStatus


@dataclass(frozen=True, slots=True)
class ParsedIKEResponse:
    """Responder facts read directly from one completed ``ike-scan`` output."""

    mode: IKEMode
    status: IKEParseStatus
    dh_groups: tuple[tuple[int, str], ...] = ()
    encryption: tuple[str, ...] = ()
    prf: tuple[str, ...] = ()
    integrity: tuple[str, ...] = ()
    transforms_offered: int | None = None
    identity_exposed: bool = False
    responder_notify: str | None = None

    @property
    def protocol_version(self) -> str:
        """Return the protocol version represented by this exchange mode."""
        return "IKEv2" if self.mode is IKEMode.IKEV2 else "IKEv1"


_DH_GROUP = re.compile(r"(?:DH_)?Group=(\d+):([A-Za-z0-9_.+\-]+)")
_ENCRYPTION = re.compile(r"Encr?=([A-Za-z0-9_.+\-]+)")
_KEY_LENGTH = re.compile(r"(?:^|[,\s]+)KeyLength=(\d+)")
_PRF = re.compile(r"(?:Prf|Hash)=([A-Za-z0-9_.+\-]+)")
_INTEGRITY = re.compile(r"Integ=([A-Za-z0-9_.+\-]+)")
_TRANSFORM_COUNT = re.compile(r"\((\d+) transforms?\)", re.IGNORECASE)
_ZERO_RESPONDER_COOKIE = re.compile(r"\bCKY-R\s*=\s*0{16}\b", re.IGNORECASE)
_ZERO_RESPONDER_SPI = re.compile(r"\bSPIr\s*=\s*0{16}\b", re.IGNORECASE)
_IKEV2_FLAGS = re.compile(r"\bflags\s*=\s*0x([0-9a-f]{2})\b", re.IGNORECASE)
_IKEV2_RESPONSE_FLAG = 0x20
_NOTIFY_PATTERNS = (
    re.compile(r"Notify[^\n(]*\(([A-Z][A-Z0-9_-]{2,})\)", re.IGNORECASE),
    re.compile(r"Notify=([A-Z][A-Z0-9_-]{2,})", re.IGNORECASE),
    re.compile(r"returned notify.*?([A-Z][A-Z0-9_-]{2,})", re.IGNORECASE),
)


def _parse_transform(
    text: str,
) -> tuple[tuple[tuple[int, str], ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Read transform identifiers exactly as ``ike-scan`` printed them."""
    groups = tuple((int(number), name) for number, name in _DH_GROUP.findall(text))
    encryption = _parse_encryption(text)
    return groups, encryption, tuple(_PRF.findall(text)), tuple(_INTEGRITY.findall(text))


def _parse_encryption(text: str) -> tuple[str, ...]:
    """Associate each key length with its encryption token on the same output line."""
    algorithms: list[str] = []
    for line in text.splitlines():
        matches = list(_ENCRYPTION.finditer(line))
        for index, match in enumerate(matches):
            window_end = matches[index + 1].start() if index + 1 < len(matches) else len(line)
            key_length = _KEY_LENGTH.search(line, match.end(), window_end)
            name = match.group(1)
            algorithms.append(f"{name}_{key_length.group(1)}" if key_length else name)
    return tuple(algorithms)


def _notify_name(text: str) -> str | None:
    """Return an explicitly named responder NOTIFY, when present."""
    for pattern in _NOTIFY_PATTERNS:
        match = pattern.search(text)
        if match is not None:
            return match.group(1).upper()
    return None


def _is_unbound_response(mode: IKEMode, text: str) -> bool:
    """Reject headers that cannot identify a protocol response."""
    if (
        _ZERO_RESPONDER_COOKIE.search(text) is not None
        or _ZERO_RESPONDER_SPI.search(text) is not None
    ):
        return True
    flags = _IKEV2_FLAGS.search(text)
    return (
        mode is IKEMode.IKEV2
        and flags is not None
        and int(flags.group(1), 16) & _IKEV2_RESPONSE_FLAG == 0
    )


def parse_ike_scan_output(
    mode: IKEMode,
    *,
    text: str,
) -> ParsedIKEResponse:
    """Classify one completed process result without size-based crypto inference."""
    notify = _notify_name(text)
    summary_rejected = bool(re.search(r"\b[1-9]\d* returned notify\b", text, re.IGNORECASE))
    if notify is not None and (summary_rejected or "Handshake returned" not in text):
        return ParsedIKEResponse(
            mode=mode,
            status=IKEParseStatus.REJECTED,
            responder_notify=notify,
        )
    if "Handshake returned" not in text:
        return ParsedIKEResponse(
            mode=mode,
            status=IKEParseStatus.NO_RESPONSE,
        )
    if _is_unbound_response(mode, text):
        return ParsedIKEResponse(
            mode=mode,
            status=IKEParseStatus.UNBOUND,
        )
    count = _TRANSFORM_COUNT.search(text)
    identity_exposed = mode is IKEMode.IKEV1_AGGRESSIVE and all(
        marker in text for marker in ("KeyExchange(", "Nonce(", "ID(Type=")
    )
    groups, encryption, prf, integrity = _parse_transform(text)
    return ParsedIKEResponse(
        mode=mode,
        status=IKEParseStatus.RESPONDED,
        dh_groups=groups,
        encryption=encryption,
        prf=prf,
        integrity=integrity,
        transforms_offered=int(count.group(1)) if count is not None else None,
        identity_exposed=identity_exposed,
        responder_notify=notify,
    )
