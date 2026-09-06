# Install and troubleshoot QuReddy

[![Diátaxis how-to](https://img.shields.io/badge/Di%C3%A1taxis-how--to-2ea44f?style=flat-square)](https://diataxis.fr/how-to-guides/)

Install the `breachsafe-qureddy` distribution with Python 3.14 or newer. Use `pipx` for
the command line application or install into a managed virtual environment.
SSH scanning works without OpenSSL. TLS scanning requires a separate OpenSSL
3.5.7 LTS binary. IKE scanning requires a separate stock `ike-scan` executable.

## Contents

1. [Prerequisites](#1-prerequisites)
2. [Install with pipx](#2-install-with-pipx)
3. [Install on macOS](#3-install-on-macos)
4. [Install on Linux](#4-install-on-linux)
5. [Install on Windows](#5-install-on-windows)
6. [Install in a virtual environment](#6-install-in-a-virtual-environment)
7. [Select OpenSSL for TLS](#7-select-openssl-for-tls)
8. [Verify the installation](#8-verify-the-installation)
9. [Upgrade or uninstall](#9-upgrade-or-uninstall)
10. [Troubleshooting](#10-troubleshooting)
11. [Related documentation](#11-related-documentation)

## 1. Prerequisites

QuReddy requires:

- Python `>=3.14`
- macOS, Linux, or Windows
- network reachability to the target
- OpenSSL 3.5.7 LTS for `scan tls` only
- stock `ike-scan` for `scan ike` only

Check Python before installing:

```bash
python3.14 --version
```

On Windows PowerShell, use the Python launcher:

```powershell
py -3.14 --version
```

## 2. Install with pipx

> **TestPyPI-only distribution.** QuReddy is available on
> [TestPyPI](https://test.pypi.org/project/breachsafe-qureddy/) only for now. Do not
> use a plain `pipx install breachsafe-qureddy` command; install from TestPyPI and
> pull runtime dependencies from PyPI:
>
> ```bash
> pipx install --python 3.14 \
>   --index-url https://test.pypi.org/simple/ \
>   --pip-args '--extra-index-url https://pypi.org/simple/' \
>   breachsafe-qureddy
> ```
>
> A public PyPI package, if authorized later, will be announced separately.

If the resolver reports that no Click version satisfies `>=8.3.3`, the PyPI
fallback is missing. TestPyPI does not mirror QuReddy's runtime dependencies;
use the two-index command above and recreate any older pipx environment with
`pipx uninstall breachsafe-qureddy` before reinstalling.

The [pipx installation guide](https://pipx.pypa.io/stable/how-to/install-pipx.html)
provides current platform instructions. After `pipx` is available:

```bash
pipx ensurepath
pipx install --python 3.14 \
  --index-url https://test.pypi.org/simple/ \
  --pip-args '--extra-index-url https://pypi.org/simple/' \
  breachsafe-qureddy
qureddy --version
```

Open a new terminal if `qureddy` is not found after `pipx ensurepath`.

QuReddy targets Python `>=3.14`. If your default `pipx` interpreter is
newer (for example 3.13), a bare `pipx install` fails with
`No matching distribution found`; pass `--python 3.14` (macOS/Linux) or use the
`py -3.14` launcher (Windows) as shown in the platform sections below.

## 3. Install on macOS

Homebrew can install Python and pipx:

```bash
brew install python@3.14 pipx
pipx ensurepath
```

Install the optional IKE collector tool separately when needed:

```bash
brew install ike-scan
ike-scan --version
```

For the current TestPyPI-only release, use both indexes:

```bash
pipx install --python "$(brew --prefix python@3.14)/bin/python3.14" \
  --index-url https://test.pypi.org/simple/ \
  --pip-args '--extra-index-url https://pypi.org/simple/' \
  breachsafe-qureddy
```

Do not select `/usr/bin/openssl`; current macOS systems expose LibreSSL at that
path, and QuReddy rejects LibreSSL for TLS scans.

Homebrew's `openssl@3.5` formula is a moving 3.5.x channel, not an exact patch
pin. If you use it, inspect the installed runtime before selecting it:

```bash
brew install openssl@3.5
QUREDDY_OPENSSL_CANDIDATE="$(brew --prefix openssl@3.5)/bin/openssl"
"$QUREDDY_OPENSSL_CANDIDATE" version
"$QUREDDY_OPENSSL_CANDIDATE" list -tls1_3 -tls-groups
```

Export the candidate only when the executable and any explicitly reported
`Library:` version are both exactly 3.5.7 and the group list contains
`X25519MLKEM768`:

```bash
export QUREDDY_OPENSSL_PQC_BIN="$QUREDDY_OPENSSL_CANDIDATE"
```

If the formula has moved, use the repository's
[checksum-pinned 3.5.7 source-build recipe](../../.github/actions/setup-openssl/action.yml)
or the [QuReddy container](docker.md); do not bypass the version gate.

## 4. Install on Linux

Install Python 3.14 and pipx from the distribution's supported package source.
Then run:

```bash
pipx ensurepath
pipx install --python python3.14 \
  --index-url https://test.pypi.org/simple/ \
  --pip-args '--extra-index-url https://pypi.org/simple/' \
  breachsafe-qureddy
```

Distribution OpenSSL versions vary. Check the installed binary:

```bash
openssl version
openssl list -tls1_3 -tls-groups
```

If the executable or any explicitly reported linked-library version is not
exactly 3.5.7, or the group list does not contain `X25519MLKEM768`, install an
supported OpenSSL 3.5.x LTS vendor build or use the repository's
[checksum-pinned 3.5.7 source-build recipe](../../.github/actions/setup-openssl/action.yml)
against the [official OpenSSL source](https://openssl-library.org/source/).
Do not substitute a current or moving release. Record the resulting path in
`QUREDDY_OPENSSL`.

## 5. Install on Windows

Install Python 3.14 and pipx, then run in PowerShell:

```powershell
py -3.14 -m pip install --user pipx
py -3.14 -m pipx ensurepath
py -3.14 -m pipx install `
  --index-url https://test.pypi.org/simple/ `
  --pip-args "--extra-index-url https://pypi.org/simple/" `
  breachsafe-qureddy
qureddy --version
```

The TestPyPI install above deliberately uses both indexes: TestPyPI supplies QuReddy,
while PyPI supplies runtime dependencies. A public PyPI package, if authorized later,
will have separate release instructions.

For a repeat TestPyPI install in PowerShell, use:

```powershell
py -3.14 -m pipx install `
  --index-url https://test.pypi.org/simple/ `
  --pip-args "--extra-index-url https://pypi.org/simple/" `
  breachsafe-qureddy
```

For TLS scans, install a trusted OpenSSL 3.5.7 LTS Windows build. QuReddy
does not bundle or endorse a third party OpenSSL binary. Set the full path:

```powershell
$env:QUREDDY_OPENSSL = "C:\Path\To\OpenSSL\bin\openssl.exe"
& $env:QUREDDY_OPENSSL version
```

SSH scans do not need this step.

## 6. Install in a virtual environment

Use this path when an application or CI job already manages an environment:

```bash
python3.14 -m venv .venv
. .venv/bin/activate
python -m pip install \
  --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ \
  breachsafe-qureddy
qureddy --version
```

On Windows PowerShell, activate with:

```powershell
py -3.14 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install `
  --index-url https://test.pypi.org/simple/ `
  --extra-index-url https://pypi.org/simple/ `
  breachsafe-qureddy
qureddy --version
```

Do not install into the operating system's managed Python environment.

## 7. Select OpenSSL for TLS

QuReddy resolves the collector binary in this order:

1. `--openssl PATH`
2. `QUREDDY_OPENSSL_PQC_BIN`
3. `QUREDDY_OPENSSL` (compatibility alias)
4. `openssl` on `PATH`

Confirm both the version and required group:

```bash
"${QUREDDY_OPENSSL_PQC_BIN:-${QUREDDY_OPENSSL:-openssl}}" version
"${QUREDDY_OPENSSL_PQC_BIN:-${QUREDDY_OPENSSL:-openssl}}" list -tls1_3 -tls-groups
```

The selected binary must report exactly OpenSSL 3.5.7 and list
`X25519MLKEM768`.

## 8. Verify the installation

The version and help commands are offline:

```bash
qureddy --version
qureddy scan ssh --help
qureddy scan tls --help
qureddy scan ike --help
```

The first network check uses SSH and needs outbound TCP port 22:

```bash
qureddy scan ssh github.com --format json > github-ssh.json
```

Verify that the result is one JSON document:

```bash
python -m json.tool github-ssh.json > /dev/null
```

On PowerShell:

```powershell
qureddy scan ssh github.com --format json |
  Set-Content -Encoding utf8 github-ssh.json
Get-Content github-ssh.json | ConvertFrom-Json | Out-Null
```

## 9. Upgrade or uninstall

For a pipx installation:

```bash
pipx upgrade \
  --index-url https://test.pypi.org/simple/ \
  --pip-args '--extra-index-url https://pypi.org/simple/' \
  breachsafe-qureddy
pipx uninstall breachsafe-qureddy
```

For a virtual environment:

```bash
python -m pip install --upgrade \
  --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ \
  breachsafe-qureddy
python -m pip uninstall breachsafe-qureddy
```

## 10. Troubleshooting

### `qureddy` is not found

Run `pipx ensurepath`, open a new terminal, and inspect:

```bash
pipx list
```

### Python version is rejected

The release metadata requires Python `>=3.14`. Point pipx at Python
3.14 explicitly:

```bash
pipx install --python python3.14 \
  --index-url https://test.pypi.org/simple/ \
  --pip-args '--extra-index-url https://pypi.org/simple/' \
  breachsafe-qureddy
```

### TLS scan exits 3

Exit `3` means the local OpenSSL dependency is missing, LibreSSL, too old,
broken, or lacks `X25519MLKEM768`. Run:

```bash
qureddy scan tls example.com -v
```

Then select a supported binary with `--openssl` or `QUREDDY_OPENSSL`.

### SSH scan exits 2

Exit `2` means the target could not be reached or its SSH identification or
KEXINIT response was malformed. Confirm DNS, the port, firewall rules, and
source IP allowlisting. Do not install OpenSSL for this failure; SSH scans do
not use it.

### IKE scan exits 2

Exit `2` means a bounded `ike-scan` probe timed out or produced output that
QuReddy could not interpret safely. Confirm UDP reachability to the target,
then inspect process diagnostics:

```bash
qureddy scan ike vpn.example.com --nat-t -vv
```

### IKE scan exits 3

Exit `3` means the stock `ike-scan` executable is missing, cannot run, or
exited nonzero. Confirm the exact executable and, if necessary, select it
explicitly:

```bash
ike-scan --version
qureddy scan ike vpn.example.com --ike-scan /absolute/path/to/ike-scan
```

Direct probes bind UDP source port `500`; NAT-T probes bind source port `4500`.
Resolve local permission or port-conflict errors instead of overriding the
source port unless the target accepts a different one.

### Machine output does not parse

Do not combine explicitly requested verbose logs with standard output. Use:

```bash
qureddy scan ssh github.com --format json > scan.json 2> scan.log
```

Without `-v`, `-vv`, or `-vvv`, successful JSON and CBOM scans keep standard
error empty.

## 11. Related documentation

- [Your first scan](../tutorials/your-first-scan.md)
- [CLI reference](../reference/cli.md)
- [Exit codes](../reference/exit-codes.md)
- [Scan SSH or SFTP](scan-ssh.md)
- [Scan an IKE endpoint](scan-ike.md)
- [Generate and validate a CBOM](generate-a-cbom.md)
