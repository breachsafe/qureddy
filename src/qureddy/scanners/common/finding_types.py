# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
"""Canonical finding-type identifiers shared by scanners and output adapters."""

from __future__ import annotations

FINDING_TYPE_PQ_SIGNATURE = "tls.cert.pq_signature"
FINDING_TYPE_CLASSICAL_SIGNATURE = "tls.cert.classical_signature"
FINDING_TYPE_WEAK_CERTIFICATE_SIGNATURE = "tls.cert.classical_signature_weak"
FINDING_TYPE_EXPIRED_CERTIFICATE = "tls.cert.expired"
FINDING_TYPE_LEGACY_PROTOCOL_OFFERED = "tls.legacy.protocol_offered"
FINDING_TYPE_CLASSICAL_PROTOCOL = "tls.kex.classical_protocol"
FINDING_TYPE_WEAK_TRANSPORT = "tls.transport.weak"
