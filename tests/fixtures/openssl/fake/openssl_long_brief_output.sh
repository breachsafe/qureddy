#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0
# Fake OpenSSL with distinct legacy and current transcript formats. The
# production parser requires the stable labels emitted by ``-brief``.
case "$1" in
    s_client)
        if [[ " $* " == *" -brief "* ]]; then
            python3 - <<'PY' >&2
print("certificate-chain-padding-" * 220)
print("Protocol version: TLSv1.3")
print("Ciphersuite: TLS_AES_256_GCM_SHA384")
print("Negotiated TLS1.3 group: X25519MLKEM768")
PY
        else
            python3 - <<'PY'
print("New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384")
print("Protocol: TLSv1.3")
print("Negotiated TLS1.3 group: X25519MLKEM768")
PY
        fi
        ;;
    *)
        echo "fake openssl: unsupported subcommand $1" >&2
        exit 2
        ;;
esac
