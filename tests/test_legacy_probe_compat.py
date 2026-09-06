# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Compatibility parsing and argv coverage for the OpenSSL 1.0 lane."""

from __future__ import annotations

from pathlib import Path

from qureddy.core.errors import QureddyError
from qureddy.scanners.tls.legacy_probe import _LEGACY_CIPHERSUITE, _candidate_ciphers
from qureddy.scanners.tls.openssl_probe import resolver


def test_legacy_openssl_cipher_line_is_parsed() -> None:
    output = "New, TLSv1/SSLv3, Cipher is RC4-SHA\n"
    match = _LEGACY_CIPHERSUITE.search(output)
    assert match is not None
    assert match.group("cipher") == "RC4-SHA"


def test_modern_and_legacy_cipher_profiles_use_different_security_suffixes(monkeypatch) -> None:
    calls: list[list[str]] = []

    def fake_run(args, *, event_prefix, timeout_seconds):
        calls.append(args)
        return type("Completed", (), {"returncode": 0, "stdout": "RC4-SHA", "stderr": ""})()

    monkeypatch.setattr("qureddy.scanners.tls.legacy_probe._run_openssl", fake_run)
    _candidate_ciphers("/modern/openssl", "-tls1", timeout_seconds=1)
    _candidate_ciphers("/legacy/openssl", "-tls1", timeout_seconds=1, legacy_compat=True)
    assert calls[0][-1].endswith("@SECLEVEL=0")
    assert not calls[1][-1].endswith("@SECLEVEL=0")


def test_legacy_runtime_resolver_accepts_1_0_2u(tmp_path: Path, monkeypatch) -> None:
    binary = tmp_path / "openssl"
    binary.write_text("fixture")
    binary.chmod(0o755)
    monkeypatch.setattr(
        resolver, "run_openssl", lambda *_args, **_kwargs: "OpenSSL 1.0.2u 20 Dec 2019"
    )
    path, dependency = resolver.resolve_legacy_openssl(str(binary), timeout_seconds=1)
    assert path == str(binary)
    assert dependency.version == "1.0.2u"


def test_legacy_runtime_resolver_records_missing_when_binary_fails(
    tmp_path: Path, monkeypatch
) -> None:
    binary = tmp_path / "openssl"
    binary.write_text("fixture")
    binary.chmod(0o755)

    def broken(*_args, **_kwargs):
        raise QureddyError("fixture failure")

    monkeypatch.setattr(resolver, "run_openssl", broken)
    path, dependency = resolver.resolve_legacy_openssl(str(binary), timeout_seconds=1)
    assert path is None
    assert dependency.failure_category is not None


def test_legacy_canonical_environment_variable_wins_over_alias(tmp_path: Path, monkeypatch) -> None:
    canonical = tmp_path / "canonical-openssl"
    alias = tmp_path / "alias-openssl"
    for binary in (canonical, alias):
        binary.write_text("fixture")
        binary.chmod(0o755)
    monkeypatch.setenv("QUREDDY_OPENSSL_WEAK_CIPHERS_BIN", str(canonical))
    monkeypatch.setenv("QUREDDY_LEGACY_OPENSSL", str(alias))
    monkeypatch.setattr(
        resolver, "run_openssl", lambda *_args, **_kwargs: "OpenSSL 1.0.2u 20 Dec 2019"
    )

    path, _ = resolver.resolve_legacy_openssl(timeout_seconds=1)

    assert path == str(canonical)


def test_legacy_environment_alias_remains_supported(tmp_path: Path, monkeypatch) -> None:
    binary = tmp_path / "alias-openssl"
    binary.write_text("fixture")
    binary.chmod(0o755)
    monkeypatch.delenv("QUREDDY_OPENSSL_WEAK_CIPHERS_BIN", raising=False)
    monkeypatch.setenv("QUREDDY_LEGACY_OPENSSL", str(binary))
    monkeypatch.setattr(
        resolver, "run_openssl", lambda *_args, **_kwargs: "OpenSSL 1.0.2u 20 Dec 2019"
    )

    path, dependency = resolver.resolve_legacy_openssl(timeout_seconds=1)

    assert path == str(binary)
    assert dependency.version == "1.0.2u"
