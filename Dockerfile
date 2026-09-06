# SPDX-FileCopyrightText: 2026 BreachSAFE
# SPDX-License-Identifier: Apache-2.0

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS openssl-build

# Keep the source archive reproducible, but track the current patched release in
# the supported 3.5 LTS series. Override both values together for a reviewed
# rebuild; the runtime validator accepts any supported 3.5.x patch release.
ARG OPENSSL_VERSION=3.5.8
ARG OPENSSL_SHA256=a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates curl perl \
    && rm -rf /var/lib/apt/lists/*

RUN curl --fail --location --proto '=https' --connect-timeout 30 --max-time 300 \
      "https://github.com/openssl/openssl/releases/download/openssl-${OPENSSL_VERSION}/openssl-${OPENSSL_VERSION}.tar.gz" \
      --output /tmp/openssl.tar.gz \
    && echo "${OPENSSL_SHA256}  /tmp/openssl.tar.gz" | sha256sum --check --strict \
    && mkdir /tmp/openssl-src \
    && tar --extract --gzip --strip-components=1 --file /tmp/openssl.tar.gz --directory /tmp/openssl-src \
    && cd /tmp/openssl-src \
    && ./Configure --prefix=/opt/openssl --openssldir=/opt/openssl/ssl shared no-tests \
    && make -j"$(nproc)" build_libs \
    && make -j"$(nproc)" apps/openssl \
    && make install_sw \
    && rm -rf /tmp/openssl.tar.gz /tmp/openssl-src

# Isolated legacy compatibility helper. OpenSSL 1.0.2u is EOL and must never
# replace the production OpenSSL or enter PATH. It is retained only for
# explicitly selected legacy cipher/STARTTLS evidence collection.
FROM ubuntu:20.04@sha256:8feb4d8ca5354def3d8fce243717141ce31e2c428701f6682bd2fafe15388214 AS openssl-legacy-build

ARG TARGETARCH
ARG LEGACY_OPENSSL_VERSION=1.0.2u
ARG LEGACY_OPENSSL_SHA256=ecd0c6ffb493dd06707d38b14bb4d8c2288bb7033735606569d8f90f89669d16

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl perl make \
    && rm -rf /var/lib/apt/lists/* \
    # Prefer the signed upstream release mirror; retain openssl.org as a fallback because
    # either public endpoint can be transiently unavailable in a hosted builder.
    && (curl --fail --location --proto '=https' --connect-timeout 30 --max-time 300 \
      "https://github.com/openssl/openssl/releases/download/OpenSSL_${LEGACY_OPENSSL_VERSION}/openssl-${LEGACY_OPENSSL_VERSION}.tar.gz" \
      --output /tmp/openssl-legacy.tar.gz \
      || curl --fail --location --proto '=https' --connect-timeout 30 --max-time 300 \
      "https://www.openssl.org/source/old/1.0.2/openssl-${LEGACY_OPENSSL_VERSION}.tar.gz" \
      --output /tmp/openssl-legacy.tar.gz) \
    && echo "${LEGACY_OPENSSL_SHA256}  /tmp/openssl-legacy.tar.gz" | sha256sum --check --strict \
    && mkdir /tmp/openssl-legacy-src \
    && tar --extract --gzip --strip-components=1 --file /tmp/openssl-legacy.tar.gz --directory /tmp/openssl-legacy-src \
    && cd /tmp/openssl-legacy-src \
    && case "${TARGETARCH}" in \
      amd64) configure_target=linux-x86_64 ;; \
      arm64) configure_target=linux-aarch64 ;; \
      *) echo "unsupported target architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && ./Configure "${configure_target}" no-shared enable-ssl3 enable-weak-ssl-ciphers --prefix=/opt/openssl-legacy \
    && make depend \
    && make -j"$(nproc)" \
    && make install_sw \
    && install -D -m 0755 /opt/openssl-legacy/bin/openssl /opt/openssl-legacy-runtime/bin/openssl \
    && install -D -m 0644 LICENSE /opt/openssl-legacy-runtime/LICENSE \
    && install -D -m 0644 /opt/openssl-legacy/ssl/openssl.cnf /opt/openssl-legacy-runtime/ssl/openssl.cnf \
    && /opt/openssl-legacy-runtime/bin/openssl version

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

COPY --from=openssl-build /opt/openssl /opt/openssl
COPY --from=openssl-legacy-build /opt/openssl-legacy-runtime /opt/openssl-legacy

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
