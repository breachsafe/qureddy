# CLI reference

[![Diátaxis reference](https://img.shields.io/badge/Di%C3%A1taxis-reference-1f6feb?style=flat-square)](https://diataxis.fr/reference/)

This page records the installed `qureddy` command surface. Option names,
defaults, accepted values, exit codes, and environment variables match the
installed help output.

## Contents

1. [Root command](#1-root-command)
2. [`qureddy scan`](#2-qureddy-scan)
3. [`qureddy scan ssh`](#3-qureddy-scan-ssh)
4. [`qureddy scan tls`](#4-qureddy-scan-tls)
5. [`qureddy scan ike`](#5-qureddy-scan-ike)
6. [Target syntax](#6-target-syntax)
7. [Output formats](#7-output-formats)
8. [Output streams](#8-output-streams)
9. [Exit codes](#9-exit-codes)
10. [Environment variables](#10-environment-variables)
11. [Related documentation](#11-related-documentation)

## 1. Root command

```text
qureddy [OPTIONS] COMMAND [ARGS]...
```

| Option | Meaning |
| --- | --- |
| `-V`, `--version` | Print the version line and exit |
| `-h`, `--help` | Print root help and exit |

| Command | Meaning |
| --- | --- |
| `help` | Print root help and exit |
| `scan` | Select the TLS, SSH, or IKE endpoint scanner |

The version line is:

```text
BreachSAFE QuReddy <version> -- https://www.breachsafe.io
```

## 2. `qureddy scan`

```text
qureddy scan [OPTIONS] COMMAND [ARGS]...
```

| Option | Meaning |
| --- | --- |
| `-h`, `--help` | Print scan group help and exit |

| Command | Meaning |
| --- | --- |
| `tls` | Scan a TLS endpoint |
| `ssh` | Scan an SSH or SFTP endpoint |
| `ike` | Scan an IKE endpoint through stock `ike-scan` |

## 3. `qureddy scan ssh`

```text
qureddy scan ssh [OPTIONS] TARGET
```

| Argument | Requirement |
| --- | --- |
| `TARGET` | Required SSH target; see [target syntax](#6-target-syntax) |

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--format` | `rich`, `json`, `cbom`, or `jsonl` | `rich` | Select output; repeated values use the last occurrence |
| `--output`, `-o` | path | standard output | Write the rendered document to a file instead of standard output; standard output stays empty; a path that cannot be opened exits `4` |
| `--output-dir` | directory | none | Run one scan and write every supported projection (`scan.json`, `scan.cdx.json`, `scan.jsonl`, `scan.rich.txt`); cannot be combined with `--output` |
| `--compact` | flag | off | Minify `--format json` or `cbom` to a single line; JSONL is always one object per line; no effect on `rich` |
| `--min-severity` | `critical`, `high`, `medium`, `low`, or `info` | none | Rich output only: hide findings below this severity; machine formats stay complete |
| `--timeout` | integer `1..300` | `8` | Socket timeout in seconds |
| `-v`, `--verbose` | count | `0` | `-v` INFO; `-vv` DEBUG; `-vvv` DEBUG plus traceability detail |
| `--json-logs` | flag | off | Write structured diagnostic logs to standard error |
| `-q`, `--quiet` | flag | off | Suppress non-error diagnostic logs |
| `--deterministic` | flag | off | Omit per-run identity (serial, timestamps, scan id and timing) so the CBOM or JSON is byte-identical across runs for content addressing |
| `-h`, `--help` | flag | n/a | Print SSH help and exit |

The SSH scanner reads the server identification and KEXINIT offer through a
direct socket. It does not run OpenSSL, authenticate, or open an SSH session.

Examples:

```bash
qureddy scan ssh github.com
qureddy scan ssh sftp.vendor.example:2222
qureddy scan ssh ssh://github.com:22 --format json
qureddy scan ssh sftp://sftp.vendor.example:2222 --format cbom
```

## 4. `qureddy scan tls`

```text
qureddy scan tls [OPTIONS] TARGET
```

| Argument | Requirement |
| --- | --- |
| `TARGET` | Required TLS target; see [target syntax](#6-target-syntax) |

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--sni` | text | target hostname | Override TLS Server Name Indication; required for IP targets that need a virtual host |
| `--openssl` | path | automatic | Select an OpenSSL 3.5.7 LTS binary |
| `--format` | `rich`, `json`, `cbom`, or `jsonl` | `rich` | Select output; repeated values use the last occurrence |
| `--output`, `-o` | path | standard output | Write the rendered document to a file instead of standard output; standard output stays empty; a path that cannot be opened exits `4` |
| `--compact` | flag | off | Minify `--format json` or `cbom` to a single line; no effect on `rich` |
| `--min-severity` | `critical`, `high`, `medium`, `low`, or `info` | none | Rich output only: hide findings below this severity; machine formats stay complete |
| `--timeout` | integer `1..300` | `30` | Timeout for each probe in seconds |
| `--retry-on` | `CATEGORY[,CATEGORY...]` | none | Retry only the named allowlisted categories: `middlebox_or_mtu_failure`, `parse_no_group`, `target_connect_failed`, or `tls_handshake_failed` |
| `--retries` | integer `0..3` | `0` | Additional attempts; requires `--retry-on` |
| `--retry-delay` | float `0.0..10.0` | `1.0` | Delay between attempts in seconds |
| `-v`, `--verbose` | count | `0` | `-v` INFO; `-vv` DEBUG; `-vvv` DEBUG plus command traceability |
| `--json-logs` | flag | off | Write structured diagnostic logs to standard error |
| `-q`, `--quiet` | flag | off | Suppress non-error diagnostic logs |
| `--log` | path | standard error | Capture the run's structured logs to a file at INFO and above; honors `--json-logs`; `-q` only quiets stderr and does not empty the explicit log; standard output stays the `--format` data channel; a bad path exits `4` |
| `--deterministic` | flag | off | Omit per-run identity (serial, timestamps, scan id and timing) so the CBOM or JSON is byte-identical across runs for content addressing |
| `-h`, `--help` | flag | n/a | Print TLS help and exit |

`--timeout` applies to each capability, handshake, legacy protocol, and
certificate probe. Total wall time can exceed the option value.

Examples:

```bash
qureddy scan tls pq.cloudflareresearch.com
qureddy scan tls 1.1.1.1:443 --sni one.one.one.one
qureddy scan tls example.com --format json
qureddy scan tls example.com --format json --compact --output scan.json
qureddy scan tls example.com --output-dir evidence/run-001
qureddy scan tls example.com --min-severity medium
qureddy scan tls example.com --format cbom
qureddy scan tls example.com --openssl /absolute/path/to/openssl
qureddy scan tls flaky.example --retry-on tls_handshake_failed --retries 3
```

## 5. `qureddy scan ike`

```text
qureddy scan ike [OPTIONS] TARGET
```

| Argument | Requirement |
| --- | --- |
| `TARGET` | Required IKE target; see [target syntax](#6-target-syntax) |

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `--ike-scan` | path or command | `ike-scan` | Select the stock executable |
| `--nat-t` | flag | off | Probe RFC 3947 framing on UDP/4500 first and use the target port as fallback per exchange mode |
| `--source-port` | integer `0..65535` | `0` | Override the UDP source port; `0` selects 500 direct or 4500 with NAT-T, and binding 500 may require privilege |
| `--format` | `rich`, `json`, `cbom`, or `jsonl` | `rich` | Select output; repeated values use the last occurrence |
| `--output`, `-o` | path | standard output | Write one rendered document to a file |
| `--output-dir` | directory | none | Run one scan and write JSON, CBOM, JSONL, and Rich projections |
| `--compact` | flag | off | Minify JSON or CBOM output |
| `--min-severity` | severity | none | Filter the Rich findings table only |
| `--timeout` | integer `1..300` | `8` | Per-probe timeout in seconds |
| `-v`, `--verbose` | count | `0` | Select INFO, DEBUG, or command traceability detail |
| `--json-logs` | flag | off | Write structured diagnostic logs to standard error |
| `-q`, `--quiet` | flag | off | Suppress non-error diagnostic logs |
| `--deterministic` | flag | off | Omit per-run CBOM identity for stable bytes |
| `-h`, `--help` | flag | n/a | Print IKE help and exit |

Examples:

```bash
qureddy scan ike vpn.example.com
qureddy scan ike vpn.example.com --nat-t
qureddy scan ike vpn.example.com --nat-t --format cbom
qureddy scan ike 192.0.2.10 --source-port 500 --format json
```

The stock backend emits low-confidence, tool-reported discovery evidence. It does not establish
an accepted proposal, authentication, Child-SA/ESP/AH posture, favorable post-quantum readiness,
or overall IPsec HNDL protection.

## 6. Target syntax

### TLS

Accepted forms:

```text
example.com
example.com:8443
tls://example.com
https://example.com:8443
1.1.1.1:443
[2001:db8::1]:443
```

TLS defaults to port `443`. Credentials, paths, query strings, fragments, and
foreign schemes are rejected before a probe runs. Use brackets around IPv6
when a port is present.

### SSH

Accepted forms:

```text
example.com
example.com:2222
ssh://example.com
sftp://example.com:2222
[2001:db8::1]:22
```

SSH defaults to port `22`. Only `ssh://` and `sftp://` schemes are accepted.
Credentials, paths, query strings, fragments, and foreign schemes are rejected
before DNS or socket access.

### IKE

Accepted forms:

```text
vpn.example.com
vpn.example.com:4500
ike://vpn.example.com
ike://[2001:db8::1]:500
```

IKE defaults to UDP/500. Credentials, paths, query strings, fragments, and foreign schemes are
rejected before the external tool runs.

## 7. Output formats

| Value | Contract |
| --- | --- |
| `rich` | Human terminal report with optional color |
| `json` | QuReddy scan document with schema version `qureddy.scan.v1` |
| `cbom` | CycloneDX 1.7 CBOM containing positively observed cryptographic assets |

`json` and `cbom` are indented by default. `jsonl` emits one finding object per
line with stable `finding_hash` identity. `--compact` minifies either to a
single line for streaming to `jq` or a log shipper. `--min-severity` trims the
`rich` findings table only; the `json` and `cbom` documents always carry every
finding, so the machine-document contract holds regardless of the filter.

`--output-dir` is the evidence-bundle mode. It executes the scanner once and
writes every supported projection from the same in-memory result, preserving the
same `scan.scan_id`, timestamps, target, findings, and evidence. The bundle
contains `scan.json` (`qureddy.scan.v1`), `scan.cdx.json` (CycloneDX 1.7),
`scan.jsonl` (one finding per line), and `scan.rich.txt` (human-readable output).

## 8. Output streams

Human output and machine documents go to standard output. Diagnostic logs and
operator hints go to standard error.

For `json` and `cbom`, the default logging posture preserves one parseable
document on standard output. A successful machine scan without explicit
verbosity leaves standard error empty. On failures, standard output still
contains the structured result and standard error may contain an operator
hint.

Under shell-level `2>&1`, the default machine modes suppress the courtesy hint
so the merged stream remains parseable. Explicit `-v`, `-vv`, or `-vvv` logs
are diagnostics and must remain on a separate stream.

## 9. Exit codes

| Code | TLS | SSH | IKE | Meaning |
| --- | --- | --- | --- | --- |
| `0` | yes | yes | yes | Scan completed |
| `2` | yes | yes | yes | Target connection, handshake, timeout, or parse failed |
| `3` | yes | no | yes | Required local executable is missing or unusable |
| `4` | yes | yes | yes | Usage or configuration error |
| `70` | yes | process fallback | process fallback | Internal QuReddy error |

See the [exit code reference](exit-codes.md) for branching examples.

## 10. Environment variables

| Variable | Scope | Meaning |
| --- | --- | --- |
| `QUREDDY_OPENSSL_PQC_BIN` | TLS | Primary OpenSSL 3.5.x path used when `--openssl` is absent |
| `QUREDDY_OPENSSL_WEAK_CIPHERS_BIN` | TLS | OpenSSL 1.0.2u path for weak-cipher compatibility probes |
| `QUREDDY_OPENSSL` / `QUREDDY_LEGACY_OPENSSL` | TLS | Compatibility aliases for the two canonical path variables |
| `QUREDDY_BLOCK_INTERNAL_TARGETS` | TLS, SSH, and IKE | Set to `1` to reject literal internal, loopback, link-local, reserved, multicast, unspecified, and known metadata-hostname targets before probing |
| `NO_COLOR` | Rich output and logs | Any value disables ANSI color |

Primary OpenSSL selection order is `--openssl`, then
`QUREDDY_OPENSSL_PQC_BIN`, then the `QUREDDY_OPENSSL` compatibility alias,
then `openssl` on `PATH`.

## 11. Related documentation

- [Install and troubleshoot](../how-to/install.md)
- [Scan an IKE endpoint](../how-to/scan-ike.md)
- [Exit codes](exit-codes.md)
- [Failure categories](failure-categories.md)
- [JSON output](json-schema.md)
- [CBOM output](cbom.md)
