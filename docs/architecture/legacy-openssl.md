# Legacy OpenSSL compatibility helper

QuReddy keeps OpenSSL 1.0.2u as an isolated compatibility helper for explicit
legacy-cipher and STARTTLS evidence collection. It is not the production TLS
implementation and is not placed on `PATH`.

## Contents

1. [Provenance](#provenance)
2. [Coverage and limits](#coverage-and-limits)

## Provenance

- Source: <https://www.openssl.org/source/old/1.0.2/openssl-1.0.2u.tar.gz>
- SHA-256: `ecd0c6ffb493dd06707d38b14bb4d8c2288bb7033735606569d8f90f89669d16`
- Release: 20 December 2019; OpenSSL 1.0.2 is end-of-life.

The Docker build compiles this source for the target architecture and exposes
the binary at `/opt/openssl-legacy/bin/openssl` through
`QUREDDY_OPENSSL_WEAK_CIPHERS_BIN`. The old `QUREDDY_LEGACY_OPENSSL` name
remains a compatibility alias. The primary `QUREDDY_OPENSSL_PQC_BIN` remains
OpenSSL 3.5.7.

## Coverage and limits

The helper exposes legacy SSLv3/TLS 1.0–1.2 cipher names, including RC4, DES,
3DES, export, NULL, IDEA, SEED, GOST, and SRP families. Its `s_client`
STARTTLS support is limited to SMTP, POP3, IMAP, FTP, and XMPP. It does not
implement the LDAP, PostgreSQL, or MySQL STARTTLS modes used by newer QuReddy
probes.

Use its output as compatibility evidence only. Do not use it as a cryptographic
library, do not make it the default probe, and do not infer that a failed legacy
handshake proves a protocol is safe.
