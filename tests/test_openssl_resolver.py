# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Hermetic coverage for cross-platform OpenSSL discovery (issue #399)."""

from __future__ import annotations

import sys
import types
from pathlib import Path
from unittest.mock import Mock

import pytest

from qureddy.core.errors import (
    LocalOpenSSLBroken,
    LocalOpenSSLIsLibreSSL,
    LocalOpenSSLLacksGroup,
    LocalOpenSSLMissing,
    LocalOpenSSLTooOld,
    LocalOpenSSLVersionMismatch,
    LocalOpenSSLVersionUnreadable,
    QureddyError,
)
from qureddy.core.models import FailureCategory, OpenSSLDependency
from qureddy.scanners.tls.openssl_probe import resolver


def test_version_key_falls_back_for_unversioned_path() -> None:
    assert resolver._version_key("/opt/openssl-dev/bin/openssl") == resolver.Version("0")  # noqa: SLF001


def test_mac_candidates_include_installed_aliases(monkeypatch: pytest.MonkeyPatch) -> None:
    which = Mock(side_effect=["/bin/openssl", None])
    monkeypatch.setattr(resolver.shutil, "which", which)

    candidates = resolver._mac_candidates()  # noqa: SLF001 -- direct builder coverage

    assert candidates == [
        "/opt/homebrew/opt/openssl@3.5/bin/openssl",
        "/usr/local/opt/openssl@3.5/bin/openssl",
        "/opt/local/bin/openssl",
        "/bin/openssl",
    ]
    assert which.call_args_list[0].args == ("openssl",)
    assert which.call_args_list[1].args == ("openssl3",)


def test_unix_candidates_are_version_sorted_and_include_fallbacks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(resolver.shutil, "which", lambda name: f"/path/{name}")

    class FakeRoot:
        def __init__(self, root: str) -> None:
            self.root = root

        def glob(self, _pattern: str) -> list[Path]:
            return [
                Path(f"{self.root}/openssl3.5/bin/openssl"),
                Path(f"{self.root}/openssl3.10/bin/openssl"),
            ]

    monkeypatch.setattr(resolver, "Path", FakeRoot)
    candidates = resolver._unix_candidates()  # noqa: SLF001 -- direct builder coverage

    assert candidates[:5] == [
        "/path/openssl3",
        "/path/openssl",
        "/usr/bin/openssl",
        "/usr/local/bin/openssl",
        "/usr/local/ssl/bin/openssl",
    ]
    assert candidates[5:] == [
        "/opt/openssl3.10/bin/openssl",
        "/opt/openssl3.5/bin/openssl",
        "/usr/local/openssl3.10/bin/openssl",
        "/usr/local/openssl3.5/bin/openssl",
    ]


def test_windows_candidates_use_environment_and_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(resolver.shutil, "which", lambda _name: None)
    monkeypatch.setattr(resolver, "_win_registry_openssl", lambda: [r"D:\OpenSSL\bin\openssl.exe"])
    for name in (
        "SystemDrive",
        "ProgramFiles",
        "ProgramW6432",
        "ProgramFiles(x86)",
        "ProgramData",
        "USERPROFILE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("SystemDrive", "D:")
    monkeypatch.setenv("USERPROFILE", r"D:\Users\tester")

    candidates = resolver._windows_candidates()  # noqa: SLF001 -- direct builder coverage

    assert candidates[0] == r"D:\Program Files\OpenSSL-Win64\bin\openssl.exe"
    assert candidates[-2:] == [
        r"D:\Users\tester\scoop\apps\openssl\current\bin\openssl.exe",
        r"D:\OpenSSL\bin\openssl.exe",
    ]


class _RegistryKey:
    def __enter__(self) -> _RegistryKey:
        return self

    def __exit__(self, *_args: object) -> None:
        return None


def test_windows_registry_candidates_skip_missing_values(monkeypatch: pytest.MonkeyPatch) -> None:
    registry = types.ModuleType("winreg")
    registry.HKEY_LOCAL_MACHINE = object()  # type: ignore[attr-defined]
    registry.HKEY_CURRENT_USER = object()  # type: ignore[attr-defined]

    def open_key(_root: object, subkey: str) -> _RegistryKey:
        if subkey.endswith("WOW6432Node\\OpenSSL"):
            raise OSError("missing")
        return _RegistryKey()

    def query_value(_key: _RegistryKey, name: str) -> tuple[str, int]:
        if name == "InstallDir":
            return (r"C:\OpenSSL", 1)
        raise OSError("missing")

    registry.OpenKey = open_key  # type: ignore[attr-defined]
    registry.QueryValueEx = query_value  # type: ignore[attr-defined]
    monkeypatch.setattr(resolver.sys, "platform", "win32")
    monkeypatch.setitem(sys.modules, "winreg", registry)

    assert resolver._win_registry_openssl() == [  # noqa: SLF001 -- direct registry coverage
        r"C:\OpenSSL/bin/openssl.exe",
        r"C:\OpenSSL/bin/openssl.exe",
    ]


@pytest.mark.parametrize(
    ("platform", "builder"),
    [
        ("darwin", "_mac_candidates"),
        ("linux", "_unix_candidates"),
        ("win32", "_windows_candidates"),
    ],
)
def test_candidate_paths_select_platform_builder_and_deduplicate_realpaths(
    monkeypatch: pytest.MonkeyPatch, platform: str, builder: str
) -> None:
    monkeypatch.setattr(resolver.sys, "platform", platform)
    monkeypatch.setattr(resolver, builder, lambda: ["/one", "/alias", "/missing"])

    class FakePath:
        def __init__(self, path: str) -> None:
            self.path = path

        def is_file(self) -> bool:
            return self.path != "/missing"

    monkeypatch.setattr(resolver, "Path", FakePath)
    monkeypatch.setattr(
        resolver.os.path, "realpath", lambda path: "/one" if path == "/alias" else path
    )

    assert resolver._candidate_paths() == ["/one"]  # noqa: SLF001 -- platform dispatch coverage


def test_registry_candidates_are_empty_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(resolver.sys, "platform", "darwin")
    assert resolver._win_registry_openssl() == []  # noqa: SLF001 -- non-Windows branch coverage


def test_candidate_paths_unknown_platform_is_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(resolver.sys, "platform", "plan9")
    assert resolver._candidate_paths() == []  # noqa: SLF001 -- unknown-platform branch coverage


@pytest.mark.parametrize(
    ("platform", "marker"),
    [("darwin", "macOS:"), ("win32", "Windows:"), ("linux", "Linux:")],
)
def test_install_guidance_is_platform_specific(
    monkeypatch: pytest.MonkeyPatch, platform: str, marker: str
) -> None:
    monkeypatch.setattr(resolver.sys, "platform", platform)
    assert marker in resolver._install_guidance()  # noqa: SLF001 -- platform guidance coverage


@pytest.mark.parametrize(
    ("category", "error_type"),
    [
        (FailureCategory.LOCAL_OPENSSL_BROKEN, LocalOpenSSLBroken),
        (FailureCategory.LOCAL_OPENSSL_IS_LIBRESSL, LocalOpenSSLIsLibreSSL),
        (FailureCategory.LOCAL_OPENSSL_LACKS_GROUP, LocalOpenSSLLacksGroup),
        (FailureCategory.LOCAL_OPENSSL_TOO_OLD, LocalOpenSSLTooOld),
        (FailureCategory.LOCAL_OPENSSL_VERSION_MISMATCH, LocalOpenSSLVersionMismatch),
        (FailureCategory.LOCAL_OPENSSL_VERSION_UNREADABLE, LocalOpenSSLVersionUnreadable),
        (FailureCategory.LOCAL_OPENSSL_MISSING, LocalOpenSSLMissing),
    ],
)
def test_explicit_override_preserves_typed_capability_failure(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    category: FailureCategory,
    error_type: type[QureddyError],
) -> None:
    explicit = tmp_path / "openssl"
    explicit.write_text("#!/bin/sh\n")
    explicit.chmod(0o755)
    dependency = OpenSSLDependency(path=str(explicit), failure_category=category)
    monkeypatch.setattr(
        resolver,
        "_validate_candidate",
        Mock(side_effect=error_type("typed failure", dependency=dependency)),
    )

    with pytest.raises(error_type) as exc_info:
        resolver.resolve_openssl_with_capability(str(explicit))

    assert exc_info.value.dependency is dependency


def test_unexpected_resolver_error_is_wrapped_as_missing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    explicit = tmp_path / "openssl"
    explicit.write_text("#!/bin/sh\n")
    explicit.chmod(0o755)
    monkeypatch.setattr(
        resolver, "_validate_candidate", Mock(side_effect=QureddyError("unexpected"))
    )

    with pytest.raises(LocalOpenSSLMissing, match="unexpected"):
        resolver.resolve_openssl_with_capability(str(explicit))


def test_primary_canonical_environment_variable_wins_over_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    canonical = tmp_path / "canonical-openssl"
    alias = tmp_path / "alias-openssl"
    for binary in (canonical, alias):
        binary.write_text("fixture")
        binary.chmod(0o755)
    dependency = OpenSSLDependency(path=str(canonical), version="3.5.7")
    monkeypatch.setenv("QUREDDY_OPENSSL_PQC_BIN", str(canonical))
    monkeypatch.setenv("QUREDDY_OPENSSL", str(alias))
    monkeypatch.setattr(resolver, "_validate_candidate", lambda path, _timeout: dependency)

    path, _ = resolver.resolve_openssl_with_capability(None)

    assert path == str(canonical)


def test_no_usable_discovered_candidate_is_typed_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("QUREDDY_OPENSSL", raising=False)
    monkeypatch.setattr(resolver, "_candidate_paths", lambda: [])
    with pytest.raises(LocalOpenSSLMissing) as exc_info:
        resolver.resolve_openssl_with_capability(None)
    assert exc_info.value.dependency is not None
    assert exc_info.value.dependency.path is None


def test_resolve_path_returns_validated_path(monkeypatch: pytest.MonkeyPatch) -> None:
    dependency = OpenSSLDependency(path="/openssl", version="3.5.7")
    monkeypatch.setattr(
        resolver, "resolve_openssl_with_capability", lambda _explicit: ("/openssl", dependency)
    )
    assert resolver.resolve_openssl_path(None) == "/openssl"


def test_validate_candidate_uses_single_probe_and_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    dependency = OpenSSLDependency(path="/openssl", version="3.5.7")
    probe = Mock(return_value=dependency)
    raise_if_unusable = Mock()
    capability = types.SimpleNamespace(probe_capability=probe, raise_if_unusable=raise_if_unusable)
    monkeypatch.setitem(sys.modules, "qureddy.scanners.tls.openssl_probe.capability", capability)

    assert resolver._validate_candidate("/openssl", 7) is dependency  # noqa: SLF001 -- boundary coverage
    probe.assert_called_once_with("/openssl", timeout_seconds=7)
    raise_if_unusable.assert_called_once_with(dependency)
