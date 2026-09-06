# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Cross-platform discovery of a usable OpenSSL 3.5.x binary.

Discovery only supplies candidates.  Every candidate, including an explicit
override, is probed through the scanner's single subprocess boundary before
it is returned.  This is important on macOS (where ``/usr/bin/openssl`` is
LibreSSL) and on Windows (where PATH often contains an unrelated OpenSSL).
"""

from __future__ import annotations

import os
import re
import shutil
import sys
from pathlib import Path, PurePath

from packaging.version import InvalidVersion, Version

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
from qureddy.scanners.tls.openssl_probe._capability_io import run_openssl
from qureddy.scanners.tls.openssl_probe._constants import (
    ENV_OVERRIDE,
    HYBRID_GROUP,
    LEGACY_ENV_OVERRIDE,
    OPENSSL_LTS_FORMULA,
    OPENSSL_LTS_LABEL,
    PINNED_OPENSSL_VERSION,
    PQC_ENV_ALIAS,
    WEAK_CIPHERS_ENV_ALIAS,
)


def _version_key(value: str) -> Version:
    """Return the canonical packaging version encoded in an OpenSSL path."""
    name = PurePath(value).parent.parent.name.removeprefix("openssl").lstrip("-_")
    try:
        return Version(name)
    except InvalidVersion:
        return Version("0")


def _present(*paths: str | None) -> list[str]:
    return [path for path in paths if path is not None]


def _win_registry_openssl() -> list[str]:
    if sys.platform != "win32":
        return []
    import winreg  # noqa: PLC0415 -- Windows-only stdlib module

    candidates: list[str] = []
    for root in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
        for subkey in (r"SOFTWARE\OpenSSL", r"SOFTWARE\WOW6432Node\OpenSSL"):
            try:
                with winreg.OpenKey(root, subkey) as key:
                    for name in ("OPENSSLDIR", "InstallDir", "InstallLocation"):
                        try:
                            base, _ = winreg.QueryValueEx(key, name)
                        except OSError:
                            continue
                        candidates.append(os.path.join(base, "bin", "openssl.exe"))  # noqa: PTH118 -- Windows path text
            except OSError:
                continue
    return candidates


def _mac_candidates() -> list[str]:
    return _present(
        f"/opt/homebrew/opt/{OPENSSL_LTS_FORMULA}/bin/openssl",
        f"/usr/local/opt/{OPENSSL_LTS_FORMULA}/bin/openssl",
        "/opt/local/bin/openssl",
        shutil.which("openssl"),
        shutil.which("openssl3"),
    )


def _unix_candidates() -> list[str]:
    candidates = _present(shutil.which("openssl3"), shutil.which("openssl"), "/usr/bin/openssl")
    candidates.extend(["/usr/local/bin/openssl", "/usr/local/ssl/bin/openssl"])
    for root in (Path("/opt"), Path("/usr/local")):
        candidates.extend(
            sorted(
                (str(path) for path in root.glob("openssl*/bin/openssl")),
                key=_version_key,
                reverse=True,
            )
        )
    return candidates


def _windows_candidates() -> list[str]:
    drive = os.environ.get("SystemDrive", "C:")  # noqa: SIM112 -- Windows variable spelling
    pf = os.environ.get("ProgramFiles", rf"{drive}\Program Files")  # noqa: SIM112
    pf64 = os.environ.get("ProgramW6432", pf)  # noqa: SIM112
    pfx86 = os.environ.get("ProgramFiles(x86)", rf"{drive}\Program Files (x86)")  # noqa: SIM112
    pdata = os.environ.get("ProgramData", rf"{drive}\ProgramData")  # noqa: SIM112
    user = os.environ.get("USERPROFILE", "")
    return _present(
        shutil.which("openssl"),
        rf"{pf64}\OpenSSL-Win64\bin\openssl.exe",
        rf"{pf}\OpenSSL-Win64\bin\openssl.exe",
        rf"{pfx86}\OpenSSL-Win32\bin\openssl.exe",
        rf"{pdata}\chocolatey\lib\openssl\tools\openssl.exe",
        rf"{pdata}\chocolatey\bin\openssl.exe",
        rf"{pf64}\Git\mingw64\bin\openssl.exe",
        rf"{pfx86}\Git\mingw64\bin\openssl.exe",
        rf"{drive}\msys64\mingw64\bin\openssl.exe",
        rf"{drive}\cygwin64\bin\openssl.exe",
        rf"{drive}\Strawberry\c\bin\openssl.exe",
        rf"{user}\scoop\apps\openssl\current\bin\openssl.exe" if user else None,
        *_win_registry_openssl(),
    )


def _candidate_paths() -> list[str]:
    """Return existence-filtered, de-duplicated platform candidates."""
    if sys.platform == "darwin":
        candidates = _mac_candidates()
    elif sys.platform.startswith(("linux", "cygwin", "msys")):
        candidates = _unix_candidates()
    elif sys.platform.startswith("win"):
        candidates = _windows_candidates()
    else:
        candidates = []

    seen: set[str] = set()
    result: list[str] = []
    for path in candidates:
        if Path(path).is_file():
            real = os.path.realpath(path)
            if real not in seen:
                seen.add(real)
                result.append(path)
    return result


def _validate_candidate(path: str, timeout_seconds: int) -> OpenSSLDependency:
    """Use the canonical capability probe; discovery must not duplicate it."""
    # Local import breaks the capability -> resolver compatibility re-export cycle.
    from qureddy.scanners.tls.openssl_probe.capability import (  # noqa: PLC0415
        probe_capability,
        raise_if_unusable,
    )

    dependency = probe_capability(path, timeout_seconds=timeout_seconds)
    raise_if_unusable(dependency)
    return dependency


def resolve_openssl_with_capability(
    explicit: str | None, *, timeout_seconds: int = 30
) -> tuple[str, OpenSSLDependency]:
    """Resolve and return a path plus its single canonical capability result."""
    override = explicit or os.environ.get(ENV_OVERRIDE) or os.environ.get(PQC_ENV_ALIAS)
    if override:
        if not Path(override).is_file() or not os.access(override, os.X_OK):
            raise LocalOpenSSLMissing(
                f"openssl path is not an executable file: {override}. {_install_guidance()}",
                dependency=_missing_dependency(override),
            )
        try:
            return override, _validate_candidate(override, timeout_seconds)
        except (
            LocalOpenSSLBroken,
            LocalOpenSSLIsLibreSSL,
            LocalOpenSSLLacksGroup,
            LocalOpenSSLMissing,
            LocalOpenSSLTooOld,
            LocalOpenSSLVersionMismatch,
            LocalOpenSSLVersionUnreadable,
        ):
            raise
        except QureddyError as error:
            raise LocalOpenSSLMissing(
                f"{override}: {error}. {_install_guidance()}",
                dependency=_missing_dependency(override),
            ) from error
    for candidate in _candidate_paths():
        try:
            return candidate, _validate_candidate(candidate, timeout_seconds)
        except QureddyError:
            continue
    raise LocalOpenSSLMissing(
        f"no working OpenSSL {OPENSSL_LTS_LABEL} LTS (with {HYBRID_GROUP}) found. {_install_guidance()}",
        dependency=_missing_dependency(None),
    )


def resolve_openssl_path(explicit: str | None) -> str:
    """Resolve an explicit/env override or the first validated platform candidate."""
    path, _ = resolve_openssl_with_capability(explicit)
    return path


def resolve_legacy_openssl(
    explicit: str | None = None, *, timeout_seconds: int = 30
) -> tuple[str | None, OpenSSLDependency]:
    """Discover the optional legacy runtime for compatibility cipher probes."""
    override = (
        explicit or os.environ.get(LEGACY_ENV_OVERRIDE) or os.environ.get(WEAK_CIPHERS_ENV_ALIAS)
    )
    candidates = (
        [override]
        if override
        else [
            "/opt/openssl-legacy/bin/openssl",
            "/opt/openssl10/bin/openssl",
            "/usr/local/openssl-legacy/bin/openssl",
        ]
    )
    for candidate in candidates:
        if not candidate or not Path(candidate).is_file() or not os.access(candidate, os.X_OK):
            continue
        try:
            version_text = run_openssl([candidate, "version"], timeout_seconds=timeout_seconds)
            match = re.search(r"^OpenSSL\s+(\d+\.\d+\.\d+[A-Za-z0-9._-]*)", version_text)
            if match is not None:
                return candidate, OpenSSLDependency(
                    name="openssl-legacy", path=candidate, version=match.group(1)
                )
        except QureddyError:
            continue
    return None, OpenSSLDependency(
        name="openssl-legacy", failure_category=FailureCategory.LOCAL_OPENSSL_MISSING
    )


def _missing_dependency(path: str | None) -> OpenSSLDependency:
    return OpenSSLDependency(path=path, failure_category=FailureCategory.LOCAL_OPENSSL_MISSING)


def _install_guidance() -> str:
    common = (
        f"pip installs QuReddy, not OpenSSL. Install a checksum-verified OpenSSL {OPENSSL_LTS_LABEL} LTS build with {HYBRID_GROUP} "
        f"(validated: {PINNED_OPENSSL_VERSION}); set {ENV_OVERRIDE}=<path> or pass --openssl PATH. "
        f"The Homebrew {OPENSSL_LTS_FORMULA} formula is a moving channel; verify the reported version."
    )
    if sys.platform == "darwin":
        return f"{common} macOS: `brew install {OPENSSL_LTS_FORMULA}`. Linux: install from a trusted vendor. Windows: install a maintained build."
    if sys.platform.startswith("win"):
        return f"{common} Windows: install a maintained OpenSSL {OPENSSL_LTS_LABEL} LTS build or use Docker. macOS: `brew install {OPENSSL_LTS_FORMULA}` is a moving channel; verify the reported version. Linux: install from a trusted vendor."
    return f"{common} Linux: install OpenSSL {OPENSSL_LTS_LABEL} from your distribution or trusted vendor. macOS: `brew install {OPENSSL_LTS_FORMULA}` is a moving channel; verify the reported version. Windows: install a maintained build."


__all__ = ["resolve_openssl_path", "resolve_openssl_with_capability"]
