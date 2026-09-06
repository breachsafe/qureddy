# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0

# Both OpenSSL builds come from the pinned toolchain image. Nothing is compiled
# here. They are product requirements everywhere and they change only on a version
# bump, so the compile belongs once at the root of the chain, not on every build of
# every consumer. Previously this file carried two from-source stages (3.5.x from
# debian-slim, 1.0.2u from ubuntu:20.04) and rebuilt both on every CI run and every
# local `docker build .`.
#
# The SERIES tag, not a patch tag: a 3.5.x bump lands here with no edit. The image
# gates its own contents to >=3.5.7,<3.6 and fails its build outside that range, so
# the tag cannot lie about what it carries.
#
# Source: paul007ex/breachsafe-container. Its python lane is python:3.14-slim-bookworm,
# the same base as the final stage below, so these binaries link the same libc.
FROM ghcr.io/paul007ex/breachsafe-container:3.14-openssl3.5 AS openssl-src

# Build the wheel from source inside the image (#253) so a fresh `docker build .`
# needs no host-built dist/ artifact. hatchling reads the static version from
# pyproject.toml, so the wheel version is intrinsic to the source, not an ARG.
FROM python:3.14-slim-bookworm@sha256:9ab8d9c8514b44f90cf0029dd42fdd7e9e211e639c8b995304cc04568dee900f AS wheel-build
RUN pip install --no-cache-dir build==1.3.0 hatchling==1.31.0
WORKDIR /src
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY LICENSES/ ./LICENSES/
COPY src/ ./src/
RUN python -m build --wheel --no-isolation --outdir /tmp/wheel

FROM python:3.14-slim-bookworm@sha256:9ab8d9c8514b44f90cf0029dd42fdd7e9e211e639c8b995304cc04568dee900f

ARG QUREDDY_VERSION=0.9.10
ARG IKE_SCAN_VERSION=1.9.5-1+b1
ARG OPENSSL_VERSION=3.5.8
LABEL org.opencontainers.image.title="QuReddy" \
      org.opencontainers.image.description="Post-quantum readiness scanner for TLS, SSH, and IKE endpoints" \
      org.opencontainers.image.source="https://github.com/breachsafe/qureddy" \
      org.opencontainers.image.licenses="Apache-2.0 AND (GPL-3.0-or-later WITH openvpn-openssl-exception)" \
      org.opencontainers.image.version="${QUREDDY_VERSION}" \
      io.breachsafe.qureddy.openssl.version="${OPENSSL_VERSION}" \
      io.breachsafe.qureddy.openssl-legacy.version="1.0.2u" \
      io.breachsafe.qureddy.ike-scan.version="${IKE_SCAN_VERSION}"

COPY --from=openssl-src /opt/openssl /opt/openssl
# Isolated legacy compatibility helper. OpenSSL 1.0.2u is EOL and must never
# replace the production OpenSSL or enter PATH. It is retained only for
# explicitly selected legacy cipher/STARTTLS evidence collection.
COPY --from=openssl-src /opt/openssl-legacy /opt/openssl-legacy

# IKE scans invoke Debian's stock ike-scan as a separate process. Keep the
# package's installed copyright and license notice with the runtime image.
RUN apt-get update \
    && apt-get install -y --no-install-recommends "ike-scan=${IKE_SCAN_VERSION}" \
    && test -r /usr/share/doc/ike-scan/copyright \
    && rm -rf /var/lib/apt/lists/*

ENV QUREDDY_OPENSSL=/opt/openssl/bin/openssl \
    QUREDDY_LEGACY_OPENSSL=/opt/openssl-legacy/bin/openssl \
    LD_LIBRARY_PATH=/opt/openssl/lib64:/opt/openssl/lib \
    PATH=/opt/openssl/bin:$PATH

# The base image is pulled by a SERIES tag, so its exact patch can move between
# builds. Assert what actually arrived matches what the labels above claim, and
# fail the build here rather than shipping an image whose labels lie. This is the
# check that replaces owning the compile. It runs after the ENV above because the
# 3.5.x build is `shared`: without LD_LIBRARY_PATH the binary produces no output and
# the comparison silently sees an empty string.
RUN set -eu; \
    got="$(/opt/openssl/bin/openssl version | cut -d' ' -f2)"; \
    [ "$got" = "${OPENSSL_VERSION}" ] || { \
      echo "base image ships OpenSSL $got, labels claim ${OPENSSL_VERSION}" >&2; exit 1; }; \
    got_legacy="$(/opt/openssl-legacy/bin/openssl version | cut -d' ' -f2)"; \
    [ "$got_legacy" = "1.0.2u" ] || { \
      echo "base image ships legacy OpenSSL $got_legacy, labels claim 1.0.2u" >&2; exit 1; }; \
    /opt/openssl/bin/openssl list -tls1_3 -tls-groups | grep -q X25519MLKEM768 \
      || { echo "base OpenSSL lacks X25519MLKEM768" >&2; exit 1; }

RUN addgroup --gid 1000 qureddy \
    && adduser --uid 1000 --gid 1000 --disabled-password --gecos "" qureddy \
    && mkdir -p /var/lib/qureddy \
    && chown qureddy:qureddy /var/lib/qureddy

# Install the wheel built in the wheel-build stage (#253). That stage emits
# exactly one wheel, so /tmp/wheel/*.whl is unambiguous.
#
# Pinned-Dependencies (issue #221, #37): OpenSSF Scorecard treats a local
# `pip install <wheel>.whl` as its pinned form, but only when the install
# argument is a SINGLE literal ending in `.whl`. Scorecard's Dockerfile shell
# parser (extractCommand) drops any word made of more than one part, so a
# `pip install .../breachsafe_qureddy-${QUREDDY_VERSION}-*.whl` (literal
# + ${ARG} expansion + glob = 3 parts) would be discarded entirely, leaving a
# bare `pip install` that scores Pinned-Dependencies 9/10 ("dependency not
# pinned by hash"). Installing via a single-part literal glob (`/tmp/wheel/*.whl`,
# no ARG expansion) keeps that word intact, so Scorecard scores 10/10. The wheel
# is a local build artifact from an earlier stage, not a remote download.
#
# QUREDDY_WHEEL_SHA256 (optional) additionally gates the install on the wheel's
# sha256 for artifact integrity; a plain `docker build` without it still builds
# and still scores Pinned-Dependencies 10/10.
ARG QUREDDY_WHEEL_SHA256=""
COPY --from=wheel-build /tmp/wheel/*.whl /tmp/wheel/
RUN set -eu; \
    wheel="$(ls /tmp/wheel/*.whl)"; \
    if [ -n "${QUREDDY_WHEEL_SHA256}" ]; then \
      echo "${QUREDDY_WHEEL_SHA256}  ${wheel}" | sha256sum --check --strict; \
    fi; \
    pip install --no-cache-dir /tmp/wheel/*.whl; \
    rm -rf /tmp/wheel; \
    python -m pip uninstall --yes pip setuptools; \
    rm -rf /usr/local/lib/python3.14/site-packages/pip \
           /usr/local/lib/python3.14/site-packages/pip-*.dist-info \
           /usr/local/lib/python3.14/site-packages/setuptools \
           /usr/local/lib/python3.14/site-packages/setuptools-*.dist-info \
           /usr/local/lib/python3.14/site-packages/pkg_resources

USER qureddy
WORKDIR /var/lib/qureddy
ENTRYPOINT ["qureddy"]
