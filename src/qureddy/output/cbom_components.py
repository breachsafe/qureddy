# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""CycloneDX crypto-asset component builders for the CBOM.

The algorithm/cipher-suite/protocol/certificate cryptographic-asset
components QuReddy positively observed, plus their classification profiles.
Split out of ``cbom.py`` to keep that module under the file-size ceiling;
the rendered CBOM is unchanged (#171).

Projection preserves observation before classification:

    ScanResult evidence
    ├── cipher suite → ciphers.py → AlgorithmProperties
    │   ├── known strength  → classicalSecurityLevel
    │   ├── known primitive  → primitive
    │   └── unknown suite   → component retained, strength omitted,
    │                         primitive = unknown
    ├── key exchange → key-exchange classifier → AlgorithmProperties
    └── signature    → signature classifier → AlgorithmProperties

CBOM outputs:

    cipher classification
    ├── AlgorithmProperties.primitive
    ├── AlgorithmProperties.classicalSecurityLevel, when sourced
    └── legacy weak finding/component verdict, when a marker matches

Unknown cipher classification remains a CBOM component. Unrated strength leaves
`classicalSecurityLevel` absent. This adapter owns projection; ciphers.py owns classification.
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from cyclonedx.model import Property
from cyclonedx.model.bom_ref import BomRef
from cyclonedx.model.component import Component, ComponentType
from cyclonedx.model.crypto import (
    AlgorithmProperties,
    CertificateProperties,
    CryptoAssetType,
    CryptoFunction,
    CryptoPrimitive,
    CryptoProperties,
    ProtocolProperties,
    ProtocolPropertiesCipherSuite,
    ProtocolPropertiesType,
)

from qureddy.core.algorithm_profile import classify_key_exchange, classify_signature_algorithm
from qureddy.core.certificate import parse_openssl_date
from qureddy.output.cbom_assets import (
    POSITIVE_OBSERVATIONS,
    add_algorithm_assets,
    add_algorithm_component,
    add_provides_edge,
    algorithm_ref,
    protocol_ref,
)
from qureddy.output.cbom_cipher import cipher_classical_bits, cipher_primitive
from qureddy.output.cbom_public_key import add_public_key_component

if TYPE_CHECKING:
    from cyclonedx.model.bom import Bom

    from qureddy.core.certificate import CertificateObservation
    from qureddy.core.models import Evidence, ScanResult

CERTIFICATE_REF = "crypto/certificate/leaf"
SELF_SIGNED_PROPERTY = "qureddy:certificate.is_self_signed"
# Evidence types handled by dedicated emitters (SSH host keys/KEX/cipher/MAC in cbom_ssh;
# legacy TLS ciphers in cbom_legacy), skipped by the generic algorithm emitter so no bom-ref
# is emitted twice and each keeps its specialized classification.
_SPECIALIZED_EVIDENCE_TYPES = frozenset(
    {
        "ssh.hostkey",
        "ssh.kex",
        "ssh.kex.weak",
        "ssh.cipher",
        "ssh.mac",
        "tls.legacy.cipher",
        "ike.cipher",
        "ike.dh_group",
        "ike.prf",
        "ike.integrity",
    }
)


def add_algorithm_components(
    bom: Bom, result: ScanResult, provides_edges: dict[str, list[str]]
) -> dict[str, str]:
    """Add one cryptographic asset per unique positively observed TLS group.

    SSH evidence gets its own SSH-specific classified components (host keys are
    signature primitives, #143; KEX groups need SSH KEX-name classification, #241/#242),
    so this shared TLS-oriented emitter skips SSH evidence types — nothing is emitted
    twice under the same bom-ref.
    """
    return add_algorithm_assets(
        bom,
        result,
        provides_edges,
        select=lambda e: (
            e.negotiated_group if e.evidence_type not in _SPECIALIZED_EVIDENCE_TYPES else None
        ),
        algorithm_properties=key_exchange_algorithm_properties,
    )


def _cipher_suite_properties(suite: str) -> AlgorithmProperties:
    """Build TLS 1.3 properties, retaining unknown suites as explicit unknown assets.

    Classification is shared with the legacy TLS and SSH cipher emitters (#315).
    A missing strength is intentional: the observed suite remains inventory evidence,
    while ``unknown`` prevents the CBOM from implying a guessed cipher family (#821).
    """
    return AlgorithmProperties(
        primitive=cipher_primitive(suite),
        classical_security_level=cipher_classical_bits(suite),
    )


def add_cipher_suite_components(
    bom: Bom, result: ScanResult, provides_edges: dict[str, list[str]]
) -> None:
    """Emit the negotiated AEAD cipher suite as its own crypto asset (#150).

    JSON carries `evidence.cipher_suite`; the CBOM previously only nested it inside
    `protocolProperties.cipherSuites`, so a core symmetric asset of the connection had
    no standalone component. Each carries the strongest observation seen for it.
    """
    add_algorithm_assets(
        bom,
        result,
        provides_edges,
        select=lambda e: e.cipher_suite,
        algorithm_properties=_cipher_suite_properties,
    )


_KEM_FUNCTIONS = (CryptoFunction.KEYGEN, CryptoFunction.ENCAPSULATE, CryptoFunction.DECAPSULATE)
_KEY_EXCHANGE_FUNCTIONS = MappingProxyType(
    {
        "kem": _KEM_FUNCTIONS,
        "key-agree": (CryptoFunction.KEYGEN,),
        "pke": (CryptoFunction.ENCAPSULATE, CryptoFunction.DECAPSULATE),
    }
)


def key_exchange_algorithm_properties(group: str) -> AlgorithmProperties | None:
    """Return a fresh AlgorithmProperties for a known group, else None (#146).

    A fresh instance per call keeps CycloneDX's mutable model out of shared module state.
    """
    spec = classify_key_exchange(group)
    if spec is None:
        return None
    return AlgorithmProperties(
        primitive=CryptoPrimitive(spec.primitive),
        parameter_set_identifier=spec.parameter_set_identifier,
        curve=spec.curve,
        crypto_functions=list(_KEY_EXCHANGE_FUNCTIONS[spec.primitive]),
        nist_quantum_security_level=spec.nist_quantum_security_level,
    )


_SIGNATURE_FUNCTIONS = (CryptoFunction.SIGN, CryptoFunction.VERIFY)


def signature_algorithm_properties(name: str) -> AlgorithmProperties | None:
    """Classify a certificate or host-key signature algorithm (#177, #201).

    Every signature is the SIGNATURE primitive with sign/verify functions. ML-DSA
    (FIPS 204) and SLH-DSA (FIPS 205) each carry their NIST security category
    (from cert_sig's single classification table); a classical signature (ECDSA,
    RSA, EdDSA, DSA) has no post-quantum resistance (nistQuantumSecurityLevel 0).
    A name we can't classify keeps a minimal algorithmProperties rather than
    fabricating a level. The PQC check runs before the classical-marker scan
    because both ML-DSA and SLH-DSA names contain the classical substring ``dsa``.
    """
    profile = classify_signature_algorithm(name)
    if profile is None:
        return None
    return AlgorithmProperties(
        primitive=CryptoPrimitive(profile.primitive),
        parameter_set_identifier=profile.parameter_set_identifier,
        crypto_functions=list(_SIGNATURE_FUNCTIONS),
        nist_quantum_security_level=profile.nist_quantum_security_level,
    )


def add_protocol_components(
    bom: Bom,
    result: ScanResult,
    algorithm_refs: dict[str, str],
    provides_edges: dict[str, list[str]],
) -> None:
    """Add one protocol asset per unique observed protocol and version."""
    positive_evidence = _positive_protocol_evidence(result)
    protocol_versions = {
        (evidence.protocol, evidence.protocol_version)
        for evidence in positive_evidence
        if evidence.protocol_version is not None
    }
    for protocol, protocol_version in sorted(protocol_versions):
        matching = [
            evidence
            for evidence in positive_evidence
            if (evidence.protocol, evidence.protocol_version) == (protocol, protocol_version)
        ]
        ref = protocol_ref(protocol, protocol_version)
        bom.components.add(
            _protocol_component(
                protocol,
                protocol_version,
                ref,
                _protocol_cipher_suites(matching, algorithm_refs),
            )
        )
        add_provides_edge(provides_edges, ref)


def _positive_protocol_evidence(result: ScanResult) -> list[Evidence]:
    """Return only positive observations that identify a protocol version."""
    return [
        evidence
        for evidence in result.evidence
        if evidence.observation_type in POSITIVE_OBSERVATIONS and evidence.protocol_version
    ]


def _protocol_cipher_suites(
    evidence: list[Evidence], algorithm_refs: dict[str, str]
) -> list[ProtocolPropertiesCipherSuite]:
    """Build deterministic cipher-suite entries for one protocol version."""
    suites = []
    for cipher_suite in sorted({item.cipher_suite for item in evidence if item.cipher_suite}):
        group_refs = sorted(
            {
                algorithm_refs[item.negotiated_group]
                for item in evidence
                if item.cipher_suite == cipher_suite and item.negotiated_group in algorithm_refs
            }
        )
        suites.append(
            ProtocolPropertiesCipherSuite(
                name=cipher_suite,
                algorithms=[BomRef(value=ref) for ref in group_refs] or None,
            )
        )
    return suites


def _protocol_component(
    protocol: str,
    protocol_version: str,
    ref: str,
    cipher_suites: list[ProtocolPropertiesCipherSuite],
) -> Component:
    """Build one CycloneDX protocol cryptographic asset."""
    protocol_type = {
        "tls": ProtocolPropertiesType.TLS,
        "ssh": ProtocolPropertiesType.SSH,
        "ike": ProtocolPropertiesType.IKE,
    }.get(protocol)
    return Component(
        name=protocol_version,
        type=ComponentType.CRYPTOGRAPHIC_ASSET,
        bom_ref=ref,
        crypto_properties=CryptoProperties(
            asset_type=CryptoAssetType.PROTOCOL,
            protocol_properties=ProtocolProperties(
                type=protocol_type,
                version=_bare_protocol_version(protocol, protocol_version),
                cipher_suites=cipher_suites or None,
            ),
        ),
    )


def _bare_protocol_version(protocol: str, protocol_version: str) -> str:
    """Return the CycloneDX bare protocol version (`1.0`, `1.3`, `2.0`).

    TLS evidence stores `"TLSv1.3"`; CycloneDX 1.7 documents this field as a bare
    version, and the SSH path already emits `"2.0"`. Strip the `TLSv` prefix so a
    consumer keying on the version sees consistent values across TLS and SSH. The
    human-facing component `name`/`bom-ref` keep the fuller label (#140).
    """
    if protocol == "tls" and protocol_version.startswith("TLSv"):
        rest = protocol_version.removeprefix("TLSv")
        # "TLSv1" is TLS 1.0; give it an explicit minor so every value is "major.minor".
        return rest if "." in rest else f"{rest}.0"
    if protocol == "ike" and protocol_version.startswith("IKEv"):
        return f"{protocol_version.removeprefix('IKEv')}.0"
    return protocol_version


def _add_signature_algorithm_component(
    bom: Bom, signature_algorithm: str, provides_edges: dict[str, list[str]]
) -> BomRef | None:
    """One cryptographic-asset component for the certificate's signature algorithm.

    Mirrors `add_algorithm_components`'s per-negotiated-group pattern —
    same reasoning: `signature_algorithm_ref` on `CertificateProperties`
    is typed `Optional[BomRef]`, a reference to a separate component, not
    a free-text string (confirmed via `inspect.signature`). Returns None
    for the "UNKNOWN" placeholder `cert_probe.py` emits when the `-text`
    output has no matching line, rather than emitting a fake component.
    """
    if signature_algorithm == "UNKNOWN":
        return None
    return add_algorithm_component(
        bom,
        name=signature_algorithm,
        ref=algorithm_ref(signature_algorithm),
        algorithm_properties=signature_algorithm_properties(signature_algorithm),
        provides_edges=provides_edges,
    )


def add_certificate_component(
    bom: Bom, certificate: CertificateObservation, provides_edges: dict[str, list[str]]
) -> None:
    """One certificate component from a real fetched+parsed cert (cert_probe.py).

    Emits two linked algorithm assets: the CA/issuer signature *over* the cert
    (``signatureAlgorithmRef``) and the cert's own subject public key
    (``subjectPublicKeyRef``, #313) — the quantum-relevant leaf key, classified via the
    shared protocol-agnostic ``add_public_key_component`` (which SSH host keys reuse in
    #291). Either ref stays unset when its algorithm is unclassifiable rather than pointing
    at a fabricated component. The installed library model does not expose CycloneDX 1.7's
    native ``certificateProperties.serialNumber`` field, so the final-byte patch adds it
    after typed serialization.
    """
    ref = CERTIFICATE_REF
    # #343: emit the subject key first so that when a fully-PQ cert's signature and subject key
    # are the same algorithm (ML-DSA-87 sig + ML-DSA-87 key), the one shared, deduped asset
    # keeps the subject key's readiness verdict; the signature ref then reuses it.
    subject_key_ref = add_public_key_component(
        bom, certificate.public_key_algorithm, certificate.public_key_bits, provides_edges
    )
    sig_alg_ref = _add_signature_algorithm_component(
        bom, certificate.signature_algorithm, provides_edges
    )
    bom.components.add(
        Component(
            name=certificate.subject,
            type=ComponentType.CRYPTOGRAPHIC_ASSET,
            bom_ref=ref,
            crypto_properties=CryptoProperties(
                asset_type=CryptoAssetType.CERTIFICATE,
                certificate_properties=CertificateProperties(
                    subject_name=certificate.subject,
                    issuer_name=certificate.issuer,
                    certificate_format="X.509",
                    not_valid_before=parse_openssl_date(certificate.not_before),
                    not_valid_after=parse_openssl_date(certificate.not_after),
                    signature_algorithm_ref=sig_alg_ref,
                    subject_public_key_ref=subject_key_ref,
                ),
            ),
            properties=[
                Property(
                    name=SELF_SIGNED_PROPERTY,
                    value=(
                        "unknown"
                        if certificate.is_self_signed is None
                        else str(certificate.is_self_signed).lower()
                    ),
                )
            ],
        )
    )
    add_provides_edge(provides_edges, ref)
