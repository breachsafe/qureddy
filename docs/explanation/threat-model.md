# Threat model and scope

[![Diátaxis explanation](https://img.shields.io/badge/Di%C3%A1taxis-explanation-8250df?style=flat-square)](https://diataxis.fr/explanation/)

QuReddy is a read-only endpoint measurement tool. It assumes an authorized
operator and a trustworthy scanner host. It reports what its TLS, SSH, and IKE
probes observe; it is not a penetration test, trust validator, or defensive
control.

## Contents

1. [Operator assumptions](#1-operator-assumptions)
2. [Scanner host assumptions](#2-scanner-host-assumptions)
3. [Network assumptions](#3-network-assumptions)
4. [Target assumptions](#4-target-assumptions)
5. [Target selection and SSRF boundary](#5-target-selection-and-ssrf-boundary)
6. [In-scope protections](#6-in-scope-protections)
7. [Out-of-scope threats](#7-out-of-scope-threats)
8. [Privacy and data handling](#8-privacy-and-data-handling)
9. [Report a vulnerability](#9-report-a-vulnerability)
10. [Related documentation](#10-related-documentation)

## 1. Operator assumptions

The operator:

- owns the target or has authorization to scan it;
- supplies the intended hostname, port, SNI, and collector path;
- understands that endpoint probes are visible in network and service logs;
- preserves the result's exit code and unknown states;
- applies remediation outside QuReddy.

QuReddy does not scan stealthily or discover targets automatically.

## 2. Scanner host assumptions

The Python interpreter, installed package, dependencies, operating system,
network resolver, selected OpenSSL binary, and selected `ike-scan` binary are
trusted.

TLS collector selection is explicit: `--openssl`, then `QUREDDY_OPENSSL_PQC_BIN`,
then the `QUREDDY_OPENSSL` compatibility alias, then `openssl` on `PATH`. A
malicious or replaced binary can fabricate output or
execute with the operator's privileges. QuReddy checks capability and records
path, version, subprocess digests, and bounded excerpts; it cannot establish
the binary's supply-chain integrity at runtime.

SSH scanning does not run OpenSSL.

IKE collector selection resolves the value of `--ike-scan` as an executable
path or command on `PATH`. A replaced executable can fabricate output or run
with the operator's privileges. QuReddy executes it without a shell, bounds its
runtime and combined output, terminates its isolated process tree on failure,
and records its resolved path, version, command, duration, return code, and
output digests. The raw parser input is excluded from serialized results.

## 3. Network assumptions

The network path:

- permits outbound TCP for TLS and SSH, and UDP/500 or UDP/4500 for IKE;
- does not transparently redirect the connection to a different endpoint;
- may contain firewalls, proxies, load balancers, or middleboxes that affect
  the observed result;
- may fail or change between probes.

A network attacker that can alter DNS or traffic can influence the
observation. QuReddy does not use an out-of-band endpoint identity channel.

## 4. Target assumptions

TLS targets return protocol output that the supported OpenSSL collector can
parse. SSH targets return an SSH identification string and KEXINIT packet
within the configured timeout. IKE targets may return a stock `ike-scan`
handshake summary, an explicit NOTIFY rejection, silence, or malformed output.

Malformed or conflicting responses become typed target or parse failures.
Target-controlled text is treated as untrusted data and is not evaluated as
code.

## 5. Target selection and SSRF boundary

QuReddy connects to whatever target it is given and does no target filtering by
default. Scanning `localhost`, an RFC1918 host, a link-local address, or a cloud
metadata endpoint such as `169.254.169.254` is intended behavior for the CLI: the
operator deliberately chooses the target.

That default is unsafe for an embedder that passes an untrusted, user-supplied
target into `parse_target`, `parse_ssh_target`, or `parse_ike_target` (for
example a hosted scan service).
There, an attacker-supplied `169.254.169.254` or `metadata.google.internal` turns
the scanner into a server-side request forgery pivot into instance metadata or
internal services.

An embedder in that position must opt into the internal-target guard by setting
`QUREDDY_BLOCK_INTERNAL_TARGETS=1` (or passing `block_internal=True` to the
parser). The guard rejects loopback, link-local, private, reserved, multicast,
unspecified, and known metadata-hostname targets before any network access. It
classifies IP literals precisely; it does NOT resolve hostnames, so a hostname
that resolves to an internal address (including DNS-rebinding) is not caught by
name. A service that accepts untrusted targets should also validate the resolved
address at connect time and run the scanner in an egress-restricted network.

## 6. In-scope protections

QuReddy provides:

- strict target parsing before network access;
- allowlisted URI schemes;
- explicit ports and bounded timeouts;
- subprocess argument vectors without a shell;
- isolated subprocess-tree termination and bounded combined output;
- bounded output excerpts and full output digests;
- typed failure and unknown states;
- standard output separation from diagnostics;
- no SSH authentication or session creation;
- CycloneDX semantic rejection of duplicate or dangling references and
  secret-like material.

These properties limit scanner behavior and preserve evidence. They do not
secure the target.

## 7. Out-of-scope threats

QuReddy does not defend against:

- a compromised scanner host, Python environment, selected OpenSSL binary, or
  selected `ike-scan` binary;
- DNS, routing, or active network interception;
- endpoint compromise or deliberate deceptive responses;
- denial of service against the scanner or target;
- side-channel attacks on the scanner host;
- TLS, SSH, or IKE vulnerability exploitation;
- decryption or key recovery;
- certificate path, trust, hostname, revocation, or transparency validation;
- complete application, source, binary, key, or certificate inventory;
- automated remediation or blocking.

Use a dedicated protocol vulnerability scanner for vulnerability assessment.
QuReddy's scope is post-quantum readiness evidence.

## 8. Privacy and data handling

QuReddy makes no telemetry, analytics, update-check, or BreachSAFE service
connection. It connects to the target named by the operator.

Results can contain target names, IP addresses, ports, SNI, certificate
metadata, algorithm names, local tool paths, bounded subprocess excerpts, and
digests. Standard output, redirected files, logs, and artifacts remain under
operator control. Operators must protect them according to their target and
environment sensitivity.

## 9. Report a vulnerability

Do not report a vulnerability in a public issue. Follow the private process in
[`SECURITY.md`](../../SECURITY.md).

Questions about expected scope or classification may use the public issue
tracker when they contain no sensitive target data.

## 10. Related documentation

- [Why hybrid post-quantum](why-hybrid-pq.md)
- [Harvest now, decrypt later](hndl.md)
- [Failure categories](../reference/failure-categories.md)
- [Security policy](../../SECURITY.md)
