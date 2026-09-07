# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Parse OpenSSL `s_client -brief` output into structured negotiation data.

Normalized for the supported OpenSSL 3.5.x LTS series (with 3.5.7 as the
validated baseline) from live
``s_client -brief`` captures:

  - Hybrid PQ negotiation announces via ``Negotiated TLS1.3 group: <name>``.
    `Peer Temp Key:` does not appear in `-brief` mode for hybrid groups.
  - Classical X25519 negotiation announces via ``Peer Temp Key: X25519, <n> bits``.
    NIST curves use ``Peer Temp Key: ECDH, <curve>, <n> bits``. `Negotiated
    TLS1.3 group:` does not appear in `-brief` for classical.

The historical spec referred to the second line as ``Server Temp Key:``;
The pinned baseline emits ``Peer Temp Key:``. The parser accepts both for
forward and backward compatibility but always anchors at line start so a
ClientHello-derived dump cannot satisfy the pattern.

Input contract: the combined stdout/stderr transcript is decoded UTF-8 text.
OpenSSL commonly writes ``s_client -brief`` status lines to stderr. The
caller joins the streams with a line boundary; comment-prefix stripping and
ANSI-escape removal remain caller responsibilities.

Parsing path:

    combined transcript
    ├── protocol version + cipher suite → ``Evidence`` fields
    ├── negotiated group → key-exchange classification
    └── missing or conflicting server evidence → explicit failure category

The parser reports observed values only. It does not infer a cipher suite or
protocol version from the command arguments when OpenSSL omits them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from qureddy.core.models import FailureCategory
from qureddy.core.signatures import classify_pqc_signature

NEGOTIATED_LINE = re.compile(
    r"^[^\S\r\n]*Negotiated[^\S\r\n]+TLS1\.3[^\S\r\n]+group:"
    r"[^\S\r\n]*(?P<group>[A-Za-z0-9_]+)[^\S\r\n]*$",
    re.MULTILINE,
)
PEER_OR_SERVER_TEMP_KEY = re.compile(
    r"^[^\S\r\n]*(?:Peer|Server)[^\S\r\n]+Temp[^\S\r\n]+Key:"
    r"[^\S\r\n]*(?:(?:ECDH|DH)[^\S\r\n]*,[^\S\r\n]*"
    r"(?P<curve>[A-Za-z0-9_.-]+)|(?P<group>[A-Za-z0-9_]+))"
    r"(?:[^\S\r\n]*,[^\S\r\n]*(?P<bits>\d{1,7})[^\S\r\n]+bits)?",
    re.MULTILINE,
)
CLIENTHELLO_LINE = re.compile(r"^\s*ClientHello\b.*$", re.MULTILINE)
PROTOCOL_VERSION = re.compile(
    r"^[^\S\r\n]*Protocol[^\S\r\n]+version:"
    r"[^\S\r\n]*(?P<protocol>TLSv\d+(?:\.\d+)?)[^\S\r\n]*$",
    re.MULTILINE,
)
CIPHERSUITE = re.compile(
    r"^[^\S\r\n]*Ciphersuite:[^\S\r\n]*(?P<cipher>[A-Z0-9_]+)[^\S\r\n]*$",
    re.MULTILINE,
)
SIGNATURE_TYPE = re.compile(
    r"^[^\S\r\n]*Signature[^\S\r\n]+type:"
    r"[^\S\r\n]*(?P<signature>[A-Za-z0-9_]+)[^\S\r\n]*$",
    re.MULTILINE,
)
HASH_USED = re.compile(
    r"^[^\S\r\n]*Hash[^\S\r\n]+used:"
    r"[^\S\r\n]*(?P<hash>[A-Za-z0-9_-]+)[^\S\r\n]*$",
    re.MULTILINE,
)


@dataclass(frozen=True, slots=True)
class ParsedNegotiation:
    """Structured outcome of parsing one probe's brief transcript.

    Plain frozen dataclass, not a Pydantic model: this is internal,
    parser-to-scanner state. The scanner converts these into the
    locked Pydantic Evidence/Asset shapes downstream.
    """

    negotiated_group: str | None = None
    protocol_version: str | None = None
    cipher_suite: str | None = None
    handshake_signature: str | None = None
    handshake_hash: str | None = None
    key_bits: int | None = None
    failure_category: FailureCategory | None = None
    notes: tuple[str, ...] = ()


def parse_brief_output(stdout: str, *, expected_group: str) -> ParsedNegotiation:
    """Parse an ``openssl s_client -brief`` transcript into negotiation data.

    Args:
        stdout: Combined decoded stdout/stderr from a real or fixture-replayed
            ``s_client`` run. The historical parameter name remains for the
            internal parser API.
        expected_group: The TLS 1.3 group the probe was configured to
            negotiate. Used as a gate: when ServerHello-derived evidence
            names a different group, the parser emits UNEXPECTED_GROUP
            rather than silently reporting whatever the server returned.

    Returns:
        ParsedNegotiation with negotiated_group set only when
        ServerHello-derived evidence supports it AND the group matches
        expected_group. Otherwise failure_category names the failure
        path with notes attributing the verdict.
    """
    protocol = _first_match(PROTOCOL_VERSION, stdout, "protocol")
    cipher = _first_match(CIPHERSUITE, stdout, "cipher")
    negotiated = _first_match(NEGOTIATED_LINE, stdout, "group")
    temp_key = _temp_key_group(stdout)

    if negotiated is not None and temp_key is not None and negotiated != temp_key:
        return _ambiguous(protocol, cipher, negotiated, temp_key)

    server_evidence = negotiated or temp_key
    if server_evidence is None:
        return _no_group(stdout, protocol, cipher, expected_group)

    if server_evidence != expected_group:
        return _unexpected(protocol, cipher, server_evidence, expected_group)

    return ParsedNegotiation(
        negotiated_group=server_evidence,
        protocol_version=protocol,
        cipher_suite=cipher,
        handshake_signature=_handshake_signature(stdout),
        handshake_hash=_first_match(HASH_USED, stdout, "hash"),
        key_bits=_temp_key_bits(stdout),
    )


def _ambiguous(
    protocol: str | None,
    cipher: str | None,
    negotiated: str,
    temp_key: str,
) -> ParsedNegotiation:
    return ParsedNegotiation(
        protocol_version=protocol,
        cipher_suite=cipher,
        failure_category=FailureCategory.PARSE_AMBIGUOUS,
        notes=(f"conflicting evidence: negotiated={negotiated} vs temp_key={temp_key}",),
    )


def _no_group(
    stdout: str,
    protocol: str | None,
    cipher: str | None,
    expected_group: str,
) -> ParsedNegotiation:
    notes: list[str] = []
    if _has_clienthello_context(stdout, expected_group):
        notes.append(f"{expected_group} appeared only in ClientHello-derived context")
    notes.append("no ServerHello-derived group line present")
    return ParsedNegotiation(
        protocol_version=protocol,
        cipher_suite=cipher,
        failure_category=FailureCategory.PARSE_NO_GROUP,
        notes=tuple(notes),
    )


def _unexpected(
    protocol: str | None,
    cipher: str | None,
    server_evidence: str,
    expected_group: str,
) -> ParsedNegotiation:
    return ParsedNegotiation(
        negotiated_group=server_evidence,
        protocol_version=protocol,
        cipher_suite=cipher,
        failure_category=FailureCategory.UNEXPECTED_GROUP,
        notes=(f"server selected {server_evidence}, probe requested {expected_group}",),
    )


def _first_match(pattern: re.Pattern[str], text: str, group_name: str) -> str | None:
    match = pattern.search(text)
    return match.group(group_name) if match else None


def _handshake_signature(text: str) -> str | None:
    """Return OpenSSL's signature type in the canonical FIPS spelling when known."""
    signature = _first_match(SIGNATURE_TYPE, text, "signature")
    if signature is None:
        return None
    classified = classify_pqc_signature(signature)
    return classified[0] if classified is not None else signature


def _temp_key_bits(text: str) -> int | None:
    """Return the observed ephemeral-key bit length when OpenSSL reports it."""
    match = PEER_OR_SERVER_TEMP_KEY.search(text)
    bits = match.group("bits") if match else None
    value = int(bits) if bits else 0
    return value if value > 0 else None


def _temp_key_group(text: str) -> str | None:
    """Return the curve name from OpenSSL's ECDH-prefixed form."""
    match = PEER_OR_SERVER_TEMP_KEY.search(text)
    if match is None:
        return None
    curve = match.group("curve")
    if curve is not None:
        return {"prime256v1": "secp256r1"}.get(curve, curve)
    return match.group("group")


def _has_clienthello_context(stdout: str, group: str) -> bool:
    return any(group in m.group(0) for m in CLIENTHELLO_LINE.finditer(stdout))
