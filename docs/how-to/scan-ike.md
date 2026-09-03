<!-- SPDX-License-Identifier: Apache-2.0 -->

# Scan an IKE endpoint

Use the optional stock `ike-scan` executable to collect lower-trust IKE discovery evidence from
an endpoint you are authorized to test.

## Contents

1. [Prerequisites](#1-prerequisites)
2. [Run a direct scan](#2-run-a-direct-scan)
3. [Probe NAT-T](#3-probe-nat-t)
4. [Write machine output](#4-write-machine-output)
5. [Interpret the result](#5-interpret-the-result)
6. [Troubleshoot](#6-troubleshoot)
7. [Verify against a local responder](#7-verify-against-a-local-responder)
8. [Related documentation](#8-related-documentation)

## 1. Prerequisites

Install QuReddy with Python 3.14 or newer. Install stock `ike-scan` separately and confirm its
version:

```bash
ike-scan --version
qureddy scan ike --help
```

The working-tree acceptance test uses `ike-scan 1.9.5`. The QuReddy wheel and current container do
not bundle the GPL-licensed executable.

Direct IKE probes use UDP source port 500 because many gateways reject requests
from an ephemeral source port. On platforms that restrict ports below 1024, grant
the `ike-scan` executable only the required bind capability or run the scan with
appropriate privilege. NAT-T probes default to source port 4500. Use
`--source-port` only when the endpoint or local policy requires an override.

If the executable is not on `PATH`, select it explicitly:

```bash
qureddy scan ike vpn.example.com --ike-scan /absolute/path/to/ike-scan
```

## 2. Run a direct scan

The default target port is UDP/500:

```bash
qureddy scan ike vpn.example.com
```

Use an explicit target port when required:

```bash
qureddy scan ike ike://vpn.example.com:500
```

## 3. Probe NAT-T

Use `--nat-t` to probe RFC 3947 framing on UDP/4500 first. QuReddy probes the target port for an
individual exchange mode only when the NAT-T probe did not return an observed responder record.

```bash
qureddy scan ike vpn.example.com --nat-t
```

## 4. Write machine output

All formats derive from one canonical scan result:

```bash
qureddy scan ike vpn.example.com --nat-t --format json > vpn.json
qureddy scan ike vpn.example.com --nat-t --format jsonl > vpn.jsonl
qureddy scan ike vpn.example.com --nat-t --format cbom > vpn.cdx.json
qureddy scan ike vpn.example.com --nat-t --output-dir evidence/vpn
```

Use `--output-dir` when the four projections must share the same scan and evidence identifiers.

## 5. Interpret the result

Stock `ike-scan` observations have low confidence. QuReddy may report responder presence, Historic
IKEv1, Aggressive Mode identity or PSK-hash exposure, weak transforms, classical KE methods, and
an explicit NOTIFY rejection. PSK-hash values are omitted. Silence remains unknown.

The backend does not prove a bound accepted proposal, peer authentication, IKE_AUTH, Child-SA,
ESP/AH, tunnel establishment, RFC 9370 additional key exchange completion, favorable post-quantum
readiness, or HNDL protection. Overall IPsec HNDL exposure remains unknown.

## 6. Troubleshoot

| Exit | Meaning | Action |
| ---: | --- | --- |
| `0` | Scan completed, including silence or explicit rejection | Inspect the structured status and findings |
| `2` | Probe timed out or output was malformed | Recheck reachability, timeout, and tool output |
| `3` | `ike-scan` is missing or unusable | Install it or pass `--ike-scan /absolute/path` |
| `4` | Target or option is invalid | Correct the command syntax |

Use `-vv` for bounded process diagnostics. Diagnostic logs go to standard error.

## 7. Verify against a local responder

The IKE acceptance suite requires stock `ike-scan` 1.9.5 and an authorized responder that
supports the documented IKEv1, IKEv1 Aggressive Mode, IKEv2, and NAT-T observations. Select the
responder explicitly when it is not listening on loopback:

```bash
export QUREDDY_IKE_LIVE_TARGET="192.0.2.10"
export QUREDDY_IKE_SCAN="/absolute/path/to/ike-scan"
export QUREDDY_IKE_PSK_TARGET="127.0.0.1:4500"
just test-ike-live
```

This lab suite is separate from the scheduled public TLS tests because a generic hosted runner
does not provide the required IPsec responder. A passing run reports every test as passed; missing
tools or an incompatible responder fail the suite.

## 8. Related documentation

- [CLI reference](../reference/cli.md)
- [Failure categories](../reference/failure-categories.md)
- [Generate a CBOM](generate-a-cbom.md)
- [IKE backend architecture](../architecture/ike-scan-backend-adr.md)
