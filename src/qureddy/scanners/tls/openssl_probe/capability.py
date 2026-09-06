# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Local OpenSSL path, version, and TLS-group capability detection."""

from __future__ import annotations

import os  # noqa: F401 -- compatibility module attribute for existing callers/tests

from packaging.version import Version

from qureddy.core.errors import (
    LocalOpenSSLBroken,
    LocalOpenSSLIsLibreSSL,
    LocalOpenSSLLacksGroup,
    LocalOpenSSLTooOld,
    LocalOpenSSLVersionMismatch,
    LocalOpenSSLVersionUnreadable,
)
from qureddy.core.models import FailureCategory, OpenSSLDependency
from qureddy.scanners.tls.openssl_probe._capability_io import (
    extract_library_version,
    extract_libressl_version,
    extract_version,
    parse_group_list,
    run_openssl,
)
from qureddy.scanners.tls.openssl_probe._constants import (
    DEFAULT_TIMEOUT_SECONDS,
    ENV_OVERRIDE,
    HYBRID_GROUP,
    OPENSSL_LTS_LABEL,
    PINNED_OPENSSL_VERSION,
    is_supported_series,
)
from qureddy.scanners.tls.openssl_probe.resolver import (
    resolve_openssl_path,
    resolve_openssl_with_capability,
)

_INSTALL_GUIDANCE = (
    f"pip installs QuReddy, not OpenSSL. Install a checksum-verified OpenSSL {OPENSSL_LTS_LABEL} "  # noqa: S608  # nosec B608 -- operator guidance, not SQL
    f"LTS build separately (validated baseline: {PINNED_OPENSSL_VERSION}), then pass "
    "--openssl PATH or set QUREDDY_OPENSSL_PQC_BIN. macOS: the Homebrew openssl@3.5 formula is "
    "a moving channel; select it only after `openssl version` reports a supported 3.5.x "
    "release for the executable and any explicitly reported linked library. Linux: install "
    "OpenSSL 3.5.x LTS from your distribution or trusted vendor. Windows: install a "
    "maintained OpenSSL 3.5.x LTS distribution and pass its full path."
)

__all__ = [
    "probe_capability",
    "raise_if_unusable",
    "resolve_openssl_path",
    "resolve_openssl_with_capability",
]


def probe_capability(
    openssl_path: str,
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
) -> OpenSSLDependency:
    """Return typed version and group support for a local OpenSSL binary."""
    version_text = run_openssl([openssl_path, "version"], timeout_seconds=timeout_seconds)
    groups_text = run_openssl(
        [openssl_path, "list", "-tls1_3", "-tls-groups"],
        timeout_seconds=timeout_seconds,
    )
    groups = parse_group_list(groups_text)
    return _dependency_from_capability(
        openssl_path,
        version_text,
        supports_groups=bool(groups),
        supports_hybrid=HYBRID_GROUP.lower() in {group.lower() for group in groups},
    )


def _dependency_from_capability(
    openssl_path: str,
    version_text: str,
    *,
    supports_groups: bool,
    supports_hybrid: bool,
) -> OpenSSLDependency:
    version = extract_version(version_text)
    library_version = extract_library_version(version_text)
    libressl_version = extract_libressl_version(version_text)
    rendered_version = _render_version(version, library_version) or libressl_version
    failure_category = _capability_failure_category(
        version_text,
        version,
        library_version,
        libressl_version,
        supports_hybrid=supports_hybrid,
    )
    return OpenSSLDependency(
        path=openssl_path,
        version=rendered_version,
        supports_tls13_groups=supports_groups,
        supports_x25519mlkem768=supports_hybrid,
        failure_category=failure_category,
    )


def _capability_failure_category(
    version_text: str,
    version: Version | None,
    library_version: Version | None,
    libressl_version: str | None,
    *,
    supports_hybrid: bool,
) -> FailureCategory | None:
    """Classify why (if at all) the probed OpenSSL is unusable, in precedence order."""
    if libressl_version is not None:
        return FailureCategory.LOCAL_OPENSSL_IS_LIBRESSL
    if version is None or ("(Library:" in version_text and library_version is None):
        return FailureCategory.LOCAL_OPENSSL_VERSION_UNREADABLE
    return _version_mismatch_category(version, library_version, supports_hybrid=supports_hybrid)


def _version_mismatch_category(
    version: Version, library_version: Version | None, *, supports_hybrid: bool
) -> FailureCategory | None:
    """Classify executable and linked-library versions using one policy."""
    for candidate in (version, library_version):
        if candidate is None:
            continue
        failure = _version_failure_category(candidate)
        if failure is not None:
            return failure
    if not supports_hybrid:
        return FailureCategory.LOCAL_OPENSSL_LACKS_GROUP
    return None


def _version_failure_category(version: Version) -> FailureCategory | None:
    """Classify one executable or linked-library version.

    ``PINNED_OPENSSL_VERSION`` is the validated runtime floor. Applying this
    predicate to both values prevents a binary with an older linked libcrypto
    from passing merely because its executable reports a newer patch.
    """
    if version < PINNED_OPENSSL_VERSION:
        return FailureCategory.LOCAL_OPENSSL_TOO_OLD
    if not is_supported_series(version):
        return FailureCategory.LOCAL_OPENSSL_VERSION_MISMATCH
    return None


def _render_version(version: Version | None, library_version: Version | None) -> str | None:
    """Render an explicit CLI/library mismatch without changing clean output."""
    if version is None:
        return None
    if library_version is not None and library_version != version:
        return f"{version} (Library: OpenSSL {library_version})"
    return str(version)


def raise_if_unusable(dep: OpenSSLDependency) -> None:
    """Translate an unusable dependency into its public typed exception."""
    category = dep.failure_category
    if category is FailureCategory.LOCAL_OPENSSL_BROKEN:
        raise LocalOpenSSLBroken(f"OpenSSL at {dep.path} exited nonzero", dependency=dep)
    if category is FailureCategory.LOCAL_OPENSSL_VERSION_UNREADABLE:
        message = (
            f"OpenSSL at {dep.path} has unparseable version output "
            f"(required: OpenSSL {OPENSSL_LTS_LABEL}.x LTS; validated baseline: "
            f"{PINNED_OPENSSL_VERSION})"
        )
        raise LocalOpenSSLVersionUnreadable(message, dependency=dep)
    if category is FailureCategory.LOCAL_OPENSSL_IS_LIBRESSL:
        raise LocalOpenSSLIsLibreSSL(_libressl_guidance(dep), dependency=dep)
    if category is FailureCategory.LOCAL_OPENSSL_TOO_OLD:
        raise LocalOpenSSLTooOld(
            f"OpenSSL {dep.version} is below the required {OPENSSL_LTS_LABEL}.x LTS series. "
            f"{_INSTALL_GUIDANCE}",
            dependency=dep,
        )
    if category is FailureCategory.LOCAL_OPENSSL_VERSION_MISMATCH:
        raise LocalOpenSSLVersionMismatch(
            f"OpenSSL {dep.version} is outside the required {OPENSSL_LTS_LABEL}.x LTS series. "
            f"{_INSTALL_GUIDANCE}",
            dependency=dep,
        )
    if category is FailureCategory.LOCAL_OPENSSL_LACKS_GROUP:
        raise LocalOpenSSLLacksGroup(
            f"OpenSSL at {dep.path} does not list {HYBRID_GROUP}",
            dependency=dep,
        )


def _libressl_guidance(dep: OpenSSLDependency) -> str:
    return (
        f"{dep.path} is LibreSSL {dep.version}, not OpenSSL — install a checksum-verified "
        f"OpenSSL {OPENSSL_LTS_LABEL}.x LTS build with {HYBRID_GROUP}, then pass "
        f"--openssl PATH or set {ENV_OVERRIDE}. On macOS, Homebrew openssl@3.5 is a "
        "moving channel; select it only after `openssl version` reports a supported 3.5.x for the "
        "executable and any explicitly reported linked library."
    )
