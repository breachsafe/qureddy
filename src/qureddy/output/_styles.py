# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Color and style tables for the Rich console adapter.

Extracted from console.py to keep that file under the 400-line hard
ceiling per docs/contributors/coding-rules.md Rule 2.2. Pure functions and tables —
no rendering, no I/O. The only consumers are the renderers in
console.py and tests under tests/test_output.py.

Color discipline (mirrored in console.py module docstring):

- PQ-positive signals (transitional_hybrid, quantum_safe, hybrid groups,
  supported capabilities) render in green so the eye can spot them.
- Routine quantum-vulnerable findings (classical X25519 from the control
  probe) render in yellow, not red. Every scan produces at least one
  classical-control finding by design; coloring it red would teach
  operators to ignore the alarm.
- Bold red is reserved for genuine breakage: classically_weak findings,
  critical/high severities, missing OpenSSL.
- Unknowns render dimly so attention falls on actionable cells.
"""

from __future__ import annotations

from rich.text import Text

from qureddy.core.models import (
    LOCAL_CAPABILITY_CATEGORIES,
    ExternalToolDependency,
    FailureCategory,
    HndlExposure,
    HygieneStatus,
    OpenSSLDependency,
    Readiness,
    Severity,
)
from qureddy.core.pqc import has_classical_half, is_hybrid_pq

DASH = "—"

# BreachSAFE brand palette (from the app's --color-bs-* tokens).
# BRAND_CYAN is the QuReddy wordmark / link color; BODY_TEXT is a soft
# slate for value/body text so it reads calmer than harsh pure white on a
# dark terminal.
BRAND_CYAN = "#3ae7f4"
BODY_TEXT = "#cbd5e1"

READINESS_STYLE: dict[Readiness, str] = {
    Readiness.QUANTUM_SAFE: "bold green",
    Readiness.TRANSITIONAL_HYBRID: "bold green",
    Readiness.QUANTUM_VULNERABLE: "yellow",
    Readiness.CLASSICALLY_WEAK: "bold red",
    Readiness.UNKNOWN: "dim",
    Readiness.NOT_APPLICABLE: "dim",
}

SEVERITY_STYLE: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "dark_orange",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

STATUS_STYLE: dict[str, str] = {
    "READY": "bold green",
    "ACCEPTABLE": "bold green",
    "ACTION NEEDED": "bold yellow",
    "NOT READY": "bold yellow",
    "FAIL": "bold red",
    "UNKNOWN": "dim",
}

VERDICT_BORDER: dict[Readiness, str] = {
    Readiness.QUANTUM_SAFE: "green",
    Readiness.TRANSITIONAL_HYBRID: "green",
    Readiness.QUANTUM_VULNERABLE: "yellow",
    Readiness.CLASSICALLY_WEAK: "red",
    Readiness.UNKNOWN: "dim",
    Readiness.NOT_APPLICABLE: "dim",
}

HNDL_STYLE: dict[HndlExposure, str] = {
    HndlExposure.PROTECTED: "bold green",
    HndlExposure.PROTECTED_DEFEASIBLE: "bold yellow",
    # At-risk is a remediation priority, not proof of an active compromise.
    HndlExposure.AT_RISK: "bold yellow",
    HndlExposure.UNKNOWN: "dim",
}

HYGIENE_STYLE: dict[HygieneStatus, str] = {
    HygieneStatus.OK: "bold green",
    HygieneStatus.ACTION_NEEDED: "bold yellow",
    # Keep red for actual scanner/crypto breakage; hygiene findings are
    # actionable remediation signals and should not look like an incident.
    HygieneStatus.WEAK: "bold yellow",
    HygieneStatus.UNKNOWN: "dim",
}

# Static recommendation text per readiness category. Recommendation copy
# is intentionally opinionated — that is the entire purpose of the row
# from a user perspective. Vendor names are deliberately avoided; the
# advice points at standards and capabilities, not products.
RECOMMENDATION_TEXT: dict[Readiness, str] = {
    Readiness.QUANTUM_SAFE: "No action required.",
    # TRANSITIONAL_HYBRID intentionally absent: this used to be a static,
    # always-"remain classical" string — false whenever a PQC cert was
    # actually served (issue #183). console.py's _cert_axis_recommendation
    # now derives this from the real tls.cert.* finding instead.
    Readiness.QUANTUM_VULNERABLE: (
        "Plan PQ migration. Enable X25519MLKEM768 on the target TLS "
        "terminator, then re-run the scan."
    ),
    Readiness.CLASSICALLY_WEAK: (
        "Migrate immediately. Weak classical crypto is exploitable "
        "today; PQ readiness is moot until this is fixed."
    ),
    Readiness.NOT_APPLICABLE: "No applicable check for this target.",
}

# Format-string template for CLASSICALLY_WEAK when a hybrid PQ group was
# ALSO negotiated (issue found scrutinizing scan tls: google.com genuinely
# holds both postures — PQ hybrid working AND legacy TLS 1.0/1.1 still
# accepted for old-client compat, confirmed live, independent of qureddy's
# own code). The old blanket "PQ readiness is moot" text (below, still
# used when no hybrid group was negotiated) is factually wrong in that
# case. Named here alongside RECOMMENDATION_TEXT rather than inlined in
# console.py, matching the existing "message copy lives in _styles.py"
# convention — filled in by console.py with hybrid_group/protocols.
CLASSICALLY_WEAK_WITH_PQC_TEMPLATE: str = (
    "PQ hybrid {hybrid_group} works.\nLegacy {protocols} remain enabled."
)


def style_readiness(readiness: Readiness) -> Text:
    """Render `readiness` as a colored Text per the readiness palette."""
    return Text(readiness.value, style=READINESS_STYLE.get(readiness, ""))


def style_severity(severity: Severity) -> Text:
    """Render `severity` as a colored Text per the severity palette."""
    return Text(severity.value, style=SEVERITY_STYLE.get(severity, ""))


def style_hndl(exposure: HndlExposure) -> Text:
    """Render HNDL exposure with a separate future-risk palette."""
    labels = {
        HndlExposure.PROTECTED: "protected",
        HndlExposure.PROTECTED_DEFEASIBLE: "protected; downgrade path remains",
        HndlExposure.AT_RISK: "at risk",
        HndlExposure.UNKNOWN: "unknown",
    }
    return Text(labels[exposure], style=HNDL_STYLE.get(exposure, "dim"))


def style_hygiene(status: HygieneStatus) -> Text:
    """Render present-day hygiene with a separate current-risk palette."""
    labels = {
        HygieneStatus.OK: "no immediate issue",
        HygieneStatus.ACTION_NEEDED: "hardening required",
        HygieneStatus.WEAK: "weak crypto; remediate",
        HygieneStatus.UNKNOWN: "unknown",
    }
    return Text(labels[status], style=HYGIENE_STYLE.get(status, "dim"))


def style_group(group: str | None) -> Text:
    """Render a TLS 1.3 group name with PQ/classical/unknown styling."""
    if not group:
        return Text(DASH, style="dim")
    if is_hybrid_pq(group):
        return Text(group, style="bold green")
    if has_classical_half(group):
        return Text(group, style="yellow")
    return Text(group)


def style_path(dep: OpenSSLDependency | ExternalToolDependency) -> Text:
    """Render `dep.path`, marking missing paths in red `(missing)`."""
    if not dep.path:
        return Text("(missing)", style="red")
    return Text(dep.path)


def style_capability(dep: OpenSSLDependency) -> Text:
    """Render `dep.supports_x25519mlkem768` as a colored yes/no."""
    if dep.supports_x25519mlkem768:
        return Text("yes", style="green")
    return Text("no", style="red")


def styled_or_dash(value: str | None) -> Text:
    """Render `value` plain, falling back to a dim em dash on None."""
    if value is None:
        return Text(DASH, style="dim")
    return Text(value)


def verdict_border_style(readiness: Readiness) -> str:
    """Return the panel-border color matching the verdict readiness."""
    return VERDICT_BORDER.get(readiness, "dim")


def compose_status(word: str, trailing: str, *, group: str | None = None) -> Text:
    """Compose a status headline: bold colored verdict word + trailing prose.

    Optionally appends a styled group name after `trailing`. Used by
    `_summary_headline_and_recommendation` to build the verdict-panel
    body in the renderer module.
    """
    out = Text(word, style=STATUS_STYLE.get(word, ""))
    out.append(trailing)
    if group is not None:
        out.append(style_group(group))
    return out


def unknown_headline(failure: FailureCategory | None) -> Text:
    """Build the UNKNOWN-readiness headline given a failure category.

    Distinguishes local-capability failures (operator's openssl is the
    problem) from probe failures (the target wasn't reachable) so the
    one-line verdict tells the user where to look.
    """
    out = Text("UNKNOWN", style=STATUS_STYLE["UNKNOWN"])
    if failure is None:
        out.append(" — no signal")
    elif failure in LOCAL_CAPABILITY_CATEGORIES:
        out.append(f" — local OpenSSL cannot test ({failure.value})")
    else:
        out.append(f" — probe failed ({failure.value})")
    return out


def unknown_recommendation(failure: FailureCategory | None) -> str:
    """Recommendation copy for the UNKNOWN-readiness branch.

    Mirrors the local/probe split in `unknown_headline` so the headline
    and recommendation always agree on which side of the boundary the
    failure sits.
    """
    if failure is None:
        return "Re-run the scan with -v for diagnostics."
    if failure is FailureCategory.LOCAL_OPENSSL_IS_LIBRESSL:
        return (
            "The openssl on this machine is LibreSSL, not OpenSSL — macOS ships "
            "LibreSSL as /usr/bin/openssl by default. Install a checksum-verified "
            "OpenSSL 3.5.x LTS build and select it with --openssl PATH or "
            "QUREDDY_OPENSSL_PQC_BIN. Homebrew openssl@3.5 is a moving channel; use it only "
            "after `openssl version` reports a supported 3.5.x for the executable and any explicitly "
            "reported linked library."
        )
    if failure is FailureCategory.LOCAL_OPENSSL_BROKEN:
        # Issue #249: this category now also covers a capability check
        # that timed out (binary present and executable, just
        # unresponsive) as well as one that exited nonzero. "Install OpenSSL"
        # is actively wrong for the first case (there's nothing to install)
        # and unhelpfully vague for the second.
        return (
            "OpenSSL failed the capability check — it either exited with an "
            "error or did not respond in time. Re-run with -v for the exact "
            "error, check --openssl points at a working binary, or increase "
            "--timeout if it may just be slow to respond (e.g. entropy "
            "exhaustion in a minimal/newly-booted environment)."
        )
    if failure in LOCAL_CAPABILITY_CATEGORIES:
        return (
            "Install OpenSSL 3.5.x LTS with PQ group support and re-run. "
            "The target's PQ posture is genuinely unknown until then."
        )
    return "Re-run the scan. Check connectivity, SNI, and that the target accepts TLS 1.3."
