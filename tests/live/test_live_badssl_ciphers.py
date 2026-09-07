# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Live cipher-rating coverage against badssl.com's deliberately weak endpoints.

`core.ciphers` rates RC4, single DES, 3DES, EXPORT, NULL, SEED, IDEA, CAMELLIA and
ARIA (#815, #824). Every existing test for those ratings passes cipher *names* to
the classifier. Nothing asserts that a scan of a host actually negotiating them
produces the rating, so a regression in the probe, the evidence builder or the CBOM
emitter would leave the unit tests green.

These hosts negotiate the weak suites on purpose and are published by badssl.com
for this use. Each expectation below was recorded from a real scan on 2026-09-06;
`min_bits` and the named suites are what the scanner emitted, not what the
classifier is expected to return in isolation.

The compatibility lane is required. OpenSSL 3.5.7 compiles out RC4 and single DES
and reaches 3DES only with `enable-weak-ssl-ciphers`, so without a 1.0.2u runtime
these endpoints negotiate nothing and every assertion here would be vacuous. The
module skips rather than fails when that runtime is absent, and
`test_compatibility_lane_is_wired` fails loudly so a silent skip cannot pass for
coverage.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from qureddy.core.ciphers import cipher_classical_bits, cipher_primitive
from qureddy.core.targets import parse_target
from qureddy.scanners.tls.openssl_probe.resolver import resolve_legacy_openssl
from qureddy.scanners.tls.scanner import TLSScanner
from tests.live.test_live_targets import _openssl_path

if TYPE_CHECKING:
    from qureddy.core.models import ScanResult

_CIPHER_EVIDENCE_TYPE = "tls.legacy.cipher"
_SYMMETRIC_PRIMITIVES = frozenset({"ae", "block-cipher", "stream-cipher", "other"})


def _legacy_openssl() -> str | None:
    path, _ = resolve_legacy_openssl()
    return path


@pytest.fixture(scope="module")
def legacy_openssl() -> str:
    path = _legacy_openssl()
    if path is None:
        pytest.skip(
            "no OpenSSL 1.0.2u compatibility runtime; set QUREDDY_LEGACY_OPENSSL "
            "(see resolve_legacy_openssl for the searched paths)"
        )
    return path


@pytest.fixture(scope="module")
def scanner(legacy_openssl: str) -> TLSScanner:
    return TLSScanner(openssl_path=_openssl_path())


def _rated_ciphers(result: ScanResult) -> dict[str, int | None]:
    """Cipher name to classical bits, for every accepted symmetric asset."""
    return {
        e.negotiated_group: cipher_classical_bits(e.negotiated_group)
        for e in result.evidence
        if e.evidence_type == _CIPHER_EVIDENCE_TYPE
        and e.negotiated_group
        and cipher_primitive(e.negotiated_group) in _SYMMETRIC_PRIMITIVES
    }


def _scan(scanner: TLSScanner, host: str) -> dict[str, int | None]:
    return _rated_ciphers(scanner.scan(parse_target(f"{host}:443")))


def test_compatibility_lane_is_wired() -> None:
    """Fail, do not skip, when the compatibility runtime is missing.

    Every other test in this module skips without it. A skipped module reports as
    a pass in most summaries, which is how the gap this file closes went unnoticed
    (see the module docstring). This one test states the prerequisite out loud.
    """
    path = _legacy_openssl()
    assert path is not None, (
        "the badssl cipher suite needs an OpenSSL 1.0.2u compatibility runtime; "
        "set QUREDDY_LEGACY_OPENSSL or install one at a path resolve_legacy_openssl searches"
    )


def test_rc4_host_rates_rc4_at_128_bits(scanner: TLSScanner) -> None:
    """rc4.badssl.com negotiates RC4, which rates 128 bits and is prohibited.

    Strength and prohibition are separate axes: RC4's key is 128 bits and RFC 7465
    bans it outright. This asserts the strength axis; `has_weak_cipher` owns the
    other and is covered by the readiness assertion below.
    """
    rated = _scan(scanner, "rc4.badssl.com")
    rc4 = {name: bits for name, bits in rated.items() if "RC4" in name}
    assert rc4, f"rc4.badssl.com negotiated no RC4 suite; got {sorted(rated)}"
    assert set(rc4.values()) == {128}, rc4


def test_rc4_md5_host_rates_rc4_md5(scanner: TLSScanner) -> None:
    """rc4-md5.badssl.com negotiates the bare RC4-MD5 suite."""
    rated = _scan(scanner, "rc4-md5.badssl.com")
    assert rated.get("RC4-MD5") == 128, rated


def test_3des_host_rates_every_suite_at_112_bits(scanner: TLSScanner) -> None:
    """3des.badssl.com offers only 3DES suites, each 112 bits (SP 800-57 Table 2).

    112 is the SWEET32 exposure this scanner exists to surface, and it is the one
    weak family the pinned 3.5.7 lane could reach with a build flag. Asserting the
    exact value keeps a future rating change from silently promoting it.
    """
    rated = _scan(scanner, "3des.badssl.com")
    assert rated, "3des.badssl.com negotiated nothing"
    assert all("DES-CBC3" in name or "3DES" in name for name in rated), rated
    assert set(rated.values()) == {112}, rated


def test_null_host_rates_null_at_zero_bits(scanner: TLSScanner) -> None:
    """null.badssl.com negotiates NULL suites, which carry zero confidentiality.

    Zero, not absent. The CycloneDX `classicalSecurityLevel` minimum is 0, so the
    rating states "no confidentiality" instead of omitting the field and leaving
    the asset unclassified.
    """
    rated = _scan(scanner, "null.badssl.com")
    null = {name: bits for name, bits in rated.items() if "NULL" in name}
    assert null, f"null.badssl.com negotiated no NULL suite; got {sorted(rated)}"
    assert set(null.values()) == {0}, null


def test_null_host_also_covers_seed_and_camellia(scanner: TLSScanner) -> None:
    """The same host's anonymous-DH suites reach SEED and CAMELLIA.

    Both were unrated before #824 and neither is reachable on the 3.5.7 lane, so
    this is the only live coverage they have.
    """
    rated = _scan(scanner, "null.badssl.com")
    seed = {name: bits for name, bits in rated.items() if "SEED" in name}
    camellia = {name: bits for name, bits in rated.items() if "CAMELLIA" in name}
    assert seed, f"no SEED suite negotiated; got {sorted(rated)}"
    assert set(seed.values()) == {128}, seed
    assert camellia, f"no CAMELLIA suite negotiated; got {sorted(rated)}"
    assert set(camellia.values()) <= {128, 256}, camellia


def test_no_accepted_cipher_is_left_unrated(scanner: TLSScanner) -> None:
    """Every suite these hosts negotiate carries a rating.

    The regression this guards is the one #815 reported: an accepted cipher
    reaching the CBOM with no `classicalSecurityLevel`, which reads as "not
    assessed" and hides the asset from any strength filter.
    """
    unrated: dict[str, list[str]] = {}
    for host in ("badssl.com", "rc4.badssl.com", "3des.badssl.com", "null.badssl.com"):
        names = [name for name, bits in _scan(scanner, host).items() if bits is None]
        if names:
            unrated[host] = sorted(names)
    assert not unrated, unrated


def test_baseline_host_reports_3des_and_camellia(scanner: TLSScanner) -> None:
    """badssl.com itself accepts 3DES and CAMELLIA alongside AES.

    The 3.5.7 lane cannot negotiate 3DES, so before the compatibility lane this
    host scanned clean. This test fails if the lane stops running.
    """
    rated = _scan(scanner, "badssl.com")
    assert any("DES-CBC3" in name for name in rated), sorted(rated)
    assert any("CAMELLIA" in name for name in rated), sorted(rated)
    assert min(bits for bits in rated.values() if bits is not None) == 112, rated
