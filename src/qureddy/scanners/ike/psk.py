# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Private handling for stock ``ike-scan --pskcrack`` output."""

from __future__ import annotations

import re
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

_FIELD_COUNT = 9
_MAX_ARTIFACT_BYTES = 64 * 1024
_HEX_FIELD = re.compile(rb"[0-9a-fA-F]+")


@contextmanager
def temporary_pskcrack_path(*, enabled: bool) -> Iterator[Path | None]:
    """Yield a private run-scoped destination and delete it on exit."""
    if not enabled:
        yield None
        return
    with TemporaryDirectory(prefix="qureddy-ike-") as directory:
        root = Path(directory)
        root.chmod(0o700)
        destination = root / "ike.psk"
        destination.touch(mode=0o600)
        destination.chmod(0o600)
        yield destination


def is_pskcrack_artifact(path: Path) -> bool:
    """Return whether a bounded file has stock ike-scan's nine-field shape."""
    content = _read_artifact(path)
    return content is not None and _has_pskcrack_shape(content)


def _read_artifact(path: Path) -> bytes | None:
    """Read one bounded, regular artifact without following symlinks."""
    try:
        if path.is_symlink() or not path.is_file():
            return None
        with path.open("rb") as artifact:
            content = artifact.read(_MAX_ARTIFACT_BYTES + 1)
    except OSError:
        return None
    if not content or len(content) > _MAX_ARTIFACT_BYTES:
        return None
    return content


def _has_pskcrack_shape(content: bytes) -> bool:
    """Validate stock ike-scan's single-line, nine-field hexadecimal shape."""
    lines = content.splitlines()
    if len(lines) != 1:
        return False
    fields = lines[0].split(b":")
    return len(fields) == _FIELD_COUNT and all(
        len(field) % 2 == 0 and _HEX_FIELD.fullmatch(field) is not None for field in fields
    )
