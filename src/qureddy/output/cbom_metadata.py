# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""``qureddy:``-namespaced ``metadata.properties`` emitters for the CBOM.

These functions append QuReddy provenance to ``bom.metadata`` (the local
OpenSSL capability flags, scan status/target identity, the evidence trail,
and per-finding verdicts). They are split out of ``cbom.py`` to keep that
module under the file-size ceiling; the rendered CBOM is unchanged (#171).
"""

from __future__ import annotations

import hashlib
from pathlib import PurePosixPath
from typing import TYPE_CHECKING, Any

from cyclonedx.model import Property

from qureddy.output.cbom_assets import (
    ENDPOINT_REF,
    algorithm_ref,
    protocol_ref,
    verdict_pairs,
)
from qureddy.output.cbom_components import CERTIFICATE_REF
from qureddy.output.cbom_interpretation import add_interpretation_properties
from qureddy.output.cbom_public_key import classify_public_key

if TYPE_CHECKING:
    from cyclonedx.model.bom import Bom

    from qureddy.core.models import Evidence, ExternalToolDependency, OpenSSLDependency, ScanResult


def openssl_tool_properties(
    dependency: OpenSSLDependency, *, reproducible: bool = False
) -> list[Property]:
    """Carry the local OpenSSL capability flags (and path) onto the tool component.

    The CBOM kept only openssl's version, dropping the flags JSON's dependencies[]
    carries. Those flags decide whether a "no hybrid found" result is a real negative
    or a prober blind-spot: a consumer can't trust the inventory without them (#151).
    The absolute local path is host-specific, so it is omitted in reproducible mode so
    two hosts observing identical crypto produce the same digest (#162/#147 audit).
    """
    properties = [
        Property(name="qureddy:collector.role", value="local-probe-runtime"),
        Property(
            name="qureddy:openssl.supports_tls13_groups",
            value=str(dependency.supports_tls13_groups).lower(),
        ),
        Property(
            name="qureddy:openssl.supports_x25519mlkem768",
            value=str(dependency.supports_x25519mlkem768).lower(),
        ),
    ]
    if dependency.path is not None and not reproducible:
        properties.append(Property(name="qureddy:openssl.path", value=dependency.path))
    return properties


def tool_dependency_properties(
    dependency: ExternalToolDependency, *, reproducible: bool = False
) -> list[Property]:
    """Carry generic external-tool provenance without host paths in deterministic mode."""
    properties = [Property(name="qureddy:collector.role", value="external-tool-adapter")]
    if dependency.path is not None and not reproducible:
        properties.append(Property(name="qureddy:collector.path", value=dependency.path))
    return properties


def add_scan_status_properties(bom: Bom, result: ScanResult) -> None:
    """Mirror scan.status/readiness/failure_category onto bom.metadata.properties.

    `bom.metadata.properties` is the standard CycloneDX extension point.
    Without this, a CBOM from a hard-failed scan (e.g. tls_handshake_failed)
    is structurally indistinguishable from a successful-but-sparse one —
    both can contain a real, valid certificate component (the certificate
    probe in cli.py runs independently of the main scan's forced-group
    probes and can succeed even when they fail), and there was previously
    no field anywhere in the CBOM itself recording that the scan failed.
    A consumer that stores/forwards only the CBOM JSON (no external exit
    code) had no way to tell these apart (issue #195).

    The readiness verdict is qureddy's headline conclusion and is carried in
    `--format json`; emitting it here keeps the CBOM self-describing so a
    consumer sees what qureddy concluded without re-deriving it (issue #132).
    """
    bom.metadata.properties.add(Property(name="qureddy:scan.status", value=result.scan.status))
    bom.metadata.properties.add(
        Property(name="qureddy:scan.readiness", value=result.summary.readiness.value)
    )
    if result.summary.interpretation is not None:
        add_interpretation_properties(bom, result.summary.interpretation)
    _add_provenance_properties(bom, result)
    _add_rollup_properties(bom, result)


def _add_provenance_properties(bom: Bom, result: ScanResult) -> None:
    """Add advisory build provenance, preserving unavailable values as absent."""
    if result.scan.provenance is not None:
        provenance = result.scan.provenance
        pairs = [("qureddy:provenance.distribution", provenance.distribution)]
        if provenance.source_revision is not None:
            pairs.append(("qureddy:provenance.source_revision", provenance.source_revision))
        if provenance.source_dirty is not None:
            pairs.append(("qureddy:provenance.source_dirty", str(provenance.source_dirty).lower()))
        if provenance.container_digest is not None:
            pairs.append(("qureddy:provenance.container_digest", provenance.container_digest))
        for name, value in pairs:
            bom.metadata.properties.add(Property(name=name, value=value))


def _add_rollup_properties(bom: Bom, result: ScanResult) -> None:
    """Add compatibility rollup fields consumed by existing CBOM clients."""
    # #309: the JSON summary rollup (finding_count + highest_severity) belongs in the CBOM too,
    # so a consumer that keys on the CBOM alone (breachsafe-ux) never falls back to native JSON.
    bom.metadata.properties.add(
        Property(name="qureddy:scan.finding_count", value=str(result.summary.finding_count))
    )
    if result.summary.highest_severity is not None:
        bom.metadata.properties.add(
            Property(
                name="qureddy:scan.highest_severity",
                value=result.summary.highest_severity.value,
            )
        )
    if result.summary.failure_category is not None:
        bom.metadata.properties.add(
            Property(
                name="qureddy:scan.failure_category",
                value=result.summary.failure_category.value,
            )
        )


def add_scan_target_metadata(bom: Bom, result: ScanResult, *, reproducible: bool = False) -> None:
    """Carry scan-identity/timing and structured target fields as metadata.properties.

    JSON exposes these; the CBOM previously kept only the emission timestamp and a
    `host:port` component name, so a CBOM-only consumer lost the scan id, timing,
    attempt count, and (critically) the SNI that determined what was actually
    probed (#152). In ``reproducible`` mode the per-run scan id and start/finish
    times are omitted so the output is content-addressable (#162).
    """
    scan = result.scan
    target = result.target
    pairs: list[tuple[str, str]] = [
        ("qureddy:scan.scanner_name", scan.scanner_name),
        ("qureddy:target.original_input", target.original_input),
        ("qureddy:target.host", target.host),
        ("qureddy:target.port", str(target.port)),
        ("qureddy:target.scheme", target.scheme),
        ("qureddy:target.locator", target.locator),
    ]
    if not reproducible:
        # total_attempts can vary with transient retries, so it is per-run too.
        pairs = [
            ("qureddy:scan.id", scan.scan_id),
            ("qureddy:scan.total_attempts", str(scan.total_attempts)),
            ("qureddy:scan.started_at", scan.started_at.isoformat()),
            ("qureddy:scan.completed_at", scan.completed_at.isoformat()),
            *pairs,
        ]
    if target.sni is not None:
        pairs.append(("qureddy:target.sni", target.sni))
    for name, value in pairs:
        bom.metadata.properties.add(Property(name=name, value=value))


def evidence_occurrences(
    result: ScanResult, *, reproducible: bool
) -> dict[str, list[dict[str, str]]]:
    """Map each crypto asset's bom-ref to its CycloneDX evidence occurrences (#287).

    Replaces the flat ``qureddy:evidence.NN.*`` metadata block: each observation is
    attached to the component it is about (``component.evidence.occurrences``), restoring
    the evidence->asset linkage the flat form dropped. Probe provenance (observation,
    role, expected group, return code, command digest) rides in ``additionalContext`` as a
    strict ``key=value`` grammar (#307) — see docs/reference/cbom-occurrence-provenance.md;
    the per-run duration is omitted in reproducible mode (#162). Evidence with no
    algorithm/protocol subject (e.g. a bare failure record) attaches to the endpoint.
    Each occurrence location names the scanned target; scanner provenance remains
    available as the ``source`` additional-context field.
    """
    occurrences: dict[str, list[dict[str, str]]] = {}
    for evidence in result.evidence:
        name = evidence.negotiated_group or evidence.cipher_suite
        if name:
            ref = algorithm_ref(name)
        elif evidence.protocol_version:
            ref = protocol_ref(evidence.protocol, evidence.protocol_version)
        else:
            # #326: evidence with no crypto subject (a bare failure/probe record) attaches to
            # the endpoint so every evidence item maps to an occurrence — no silent drop.
            ref = ENDPOINT_REF
        fields = _provenance_fields(evidence, name, reproducible=reproducible)
        occurrence = {"location": result.target.locator, "additionalContext": "; ".join(fields)}
        for occurrence_ref in _occurrence_refs(evidence, ref):
            entries = occurrences.setdefault(occurrence_ref, [])
            if occurrence not in entries:
                entries.append(occurrence)
    return occurrences


def _occurrence_refs(evidence: Evidence, default_ref: str) -> tuple[str, ...]:
    """Return each emitted asset ref described by one evidence record (#796)."""
    certificate = evidence.certificate_record
    if certificate is None:
        return (default_ref,)
    refs = [CERTIFICATE_REF]
    if certificate.signature_algorithm != "UNKNOWN":
        refs.append(algorithm_ref(certificate.signature_algorithm))
    public_key = classify_public_key(certificate.public_key_algorithm, certificate.public_key_bits)
    if public_key is not None:
        refs.append(algorithm_ref(public_key.name))
    return tuple(dict.fromkeys(refs))


def _provenance_fields(evidence: Evidence, name: str | None, *, reproducible: bool) -> list[str]:
    """Render one evidence item's probe provenance as the strict ``key=value`` field list (#307).

    Strict "key=value" pairs (joined by "; " by the caller) so a consumer reads each provenance
    field without scraping prose — the fragility the flat layer had, in miniature. Keys are
    lower_snake_case; no value contains "; " or "=", so split-then-partition is a total parse.
    Grammar contract: docs/reference/cbom-occurrence-provenance.md.
    """
    fields = [
        f"observation={evidence.observation_type.value}",
        f"evidence_type={evidence.evidence_type}",
        f"confidence={evidence.confidence.value}",  # #326: preserve confidence as a field
        f"source={evidence.source}",
    ]
    # #326: co-observed cipher suite as a field (when it isn't already the occurrence subject).
    if evidence.cipher_suite and evidence.cipher_suite != name:
        fields.append(f"cipher_suite={evidence.cipher_suite}")
    if evidence.probe_role:
        fields.append(f"role={evidence.probe_role.value}")
    if evidence.expected_group:
        fields.append(f"expected={evidence.expected_group}")
    probe = evidence.probe_result
    if probe is not None:
        executable = (
            PurePosixPath(probe.command.executable).name
            if reproducible
            else probe.command.executable
        )
        command = " ".join([executable, *probe.command.args])
        # Full digest (not truncated) so it keeps the reproducibility guarantee: the
        # command is attributed by basename, not host path, and bytes stay stable (#207).
        fields.extend(
            (
                f"return_code={probe.return_code}",
                f"command_sha256={hashlib.sha256(command.encode()).hexdigest()}",
            )
        )
        if not reproducible:
            fields.append(f"duration_ms={probe.duration_ms}")
    return fields


# CycloneDX requires annotation.timestamp; reproducible mode pins it to the Unix epoch so
# two hosts scanning the same target produce byte-identical, content-addressable output
# (the same reason serialNumber/metadata.timestamp/scan times are dropped in that mode, #162).
_REPRODUCIBLE_TIMESTAMP = "1970-01-01T00:00:00+00:00"


def finding_annotations(
    result: ScanResult, *, reproducible: bool
) -> tuple[list[dict[str, Any]], dict[str, list[dict[str, str]]]]:
    """Build native finding annotations plus per-component verdict properties (#287).

    Replaces the flat ``qureddy:finding.NN.*`` metadata block. Each finding becomes a
    CycloneDX ``annotation`` whose ``subjects`` point at the crypto asset it is about,
    carrying the title + full description (with standards citations — subsumes #285). The
    machine verdict (readiness/severity/rule_id) is returned per subject ref so the caller
    attaches it as queryable ``properties`` on that component; the first finding per subject
    sets the verdict so a component carries one, not several, verdict blocks.
    """
    timestamp = _REPRODUCIBLE_TIMESTAMP if reproducible else result.scan.completed_at.isoformat()
    annotations: list[dict[str, Any]] = []
    verdicts: dict[str, list[dict[str, str]]] = {}
    for index, finding in enumerate(result.findings):
        if finding.negotiated_group:
            subject = algorithm_ref(finding.negotiated_group)
        elif finding.algorithm:
            subject = algorithm_ref(finding.algorithm)
        elif finding.protocol_version:
            subject = protocol_ref(finding.protocol, finding.protocol_version)
        else:
            subject = ENDPOINT_REF
        # Index-prefixed bom-ref: rule_id is not unique (e.g. two legacy protocols fire
        # tls.legacy.protocol_offered), and every bom-ref in the document must be unique.
        annotations.append(
            {
                "bom-ref": f"annotation/{index:02d}-{finding.rule_id}",
                "subjects": [subject],
                "annotator": {
                    "component": {
                        "bom-ref": "tool/qureddy",
                        "name": "qureddy",
                        "type": "application",
                    }
                },
                "timestamp": timestamp,
                "text": f"{finding.title}\n{finding.description}",
            }
        )
        verdicts.setdefault(
            subject,
            [
                {"name": name, "value": value}
                for name, value in verdict_pairs(
                    finding.readiness.value, finding.severity.value, finding.rule_id
                )
            ],
        )
    return annotations, verdicts
