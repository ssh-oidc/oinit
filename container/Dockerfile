# syntax=docker/dockerfile:1.7

# oinit container images.
#
# Build context is the repository root, e.g.:
#   docker build -f container/Dockerfile --target oinit-ca -t sshoidc/oinit-ca .
#
# Targets:
#   oinit-ca      REST CA that signs SSH certificates; validates OIDC tokens
#                 against motley_cue (see container/README.md)
#   oinit-sshd    OpenSSH host payload: sshd + oinit-shell/oinit-switch, the
#                 container equivalent of the oinit-openssh package
#   oinit         client CLI (oinit add/list/match) for CI and testing

ARG GO_VERSION=1.24
ARG OINIT_VERSION=dev
ARG DEBIAN_RELEASE=bookworm

# ---------------------------------------------------------------------------
# Build all oinit binaries (static, CGO disabled)
# ---------------------------------------------------------------------------
FROM golang:${GO_VERSION}-alpine AS builder

ARG OINIT_VERSION
ENV CGO_ENABLED=0 GOTOOLCHAIN=local

COPY . /src/oinit
WORKDIR /src/oinit

RUN for bin in oinit oinit-ca oinit-shell oinit-switch; do \
        go build -trimpath \
            -ldflags="-s -w -X main.version=${OINIT_VERSION}" \
            -o "/out/${bin}" "./cmd/${bin}" \
        || exit 1; \
    done

# ---------------------------------------------------------------------------
# CA service: signs SSH certificates, validates tokens against motley_cue
# ---------------------------------------------------------------------------
FROM alpine:3.20 AS oinit-ca

RUN apk add --no-cache \
        ca-certificates \
        openssh-client \
        su-exec

# The CA runs as an unprivileged user; its key material lives in /etc/oinit
# (a volume). The entrypoint generates the default host/user CA key pairs on
# first start and then drops privileges.
RUN addgroup -S oinit 2>/dev/null; \
    adduser -S oinit -H -h /var/oinit -s /sbin/nologin -G oinit 2>/dev/null; \
    install -d -m 0750 -o oinit -g oinit /var/oinit

COPY --from=builder /out/oinit-ca /usr/bin/oinit-ca
COPY configs/config.sample.ini /usr/share/oinit-ca/config.sample.ini
COPY container/oinit-ca-entrypoint.sh /sbin/oinit-ca-entrypoint
RUN chmod 0755 /sbin/oinit-ca-entrypoint

EXPOSE 8082
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["/bin/sh", "-c", "wget -q -T 3 -O /dev/null http://127.0.0.1:${OINIT_HEALTH_PORT:-8082}/health"]
ENTRYPOINT ["/sbin/oinit-ca-entrypoint"]
CMD ["-c", "/etc/oinit/ca-config.ini"]

# ---------------------------------------------------------------------------
# SSH host: sshd + oinit-shell + oinit-switch (oinit-openssh package container)
#
# Login flow: users authenticate with an SSH certificate issued by an oinit
# CA, signed as user "oinit" (or the provisioned username). sshd hands the
# session to oinit-shell, which runs oinit-switch to su to the target account.
#
# Accounts are NOT provisioned by this image. Two supported account sources:
#   - files:     read-only bind mounts over /etc/passwd, /etc/group,
#                /etc/shadow, /etc/nsswitch.conf of the host
#   - LDAP:      mount an nslcd.conf at /etc/nslcd.conf (see
#                configs/nslcd.conf.template); the entrypoint then switches
#                NSS to "files ldap" and starts nslcd
# For hosts where motley_cue provisions accounts itself, prefer the
# motley_cue allinone-oinit or sshd-oinit images, which embed the same
# oinit-shell/oinit-switch binaries.
# ---------------------------------------------------------------------------
FROM debian:${DEBIAN_RELEASE}-slim AS oinit-sshd

ARG DEBIAN_RELEASE

ENV DEBIAN_FRONTEND=noninteractive

RUN printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d \
    && chmod 0755 /usr/sbin/policy-rc.d

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash \
        ca-certificates \
        libcap2-bin \
        libnss-ldapd \
        nslcd \
        openssh-client \
        openssh-server \
        runit \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    && rm -f /usr/sbin/policy-rc.d

# Do not bake host keys into a public image; they live in /state. The nslcd
# package installs a default /etc/nslcd.conf which must not exist by default:
# the entrypoint enables LDAP only when the operator mounts one.
RUN rm -f /etc/ssh/ssh_host_* /etc/nslcd.conf \
    && sed -i 's|^HostKey /etc/ssh/|#HostKey /etc/ssh/|' /etc/ssh/sshd_config

COPY --from=builder /out/oinit-shell /usr/bin/oinit-shell
COPY --from=builder /out/oinit-switch /usr/bin/oinit-switch

# oinit system user with oinit-shell as login shell (as the oinit-openssh
# postinstall script does on distribution hosts).
RUN chmod 0755 /usr/bin/oinit-shell /usr/bin/oinit-switch \
    && useradd --system --badname \
        --shell /usr/bin/oinit-shell \
        --home-dir /var/oinit-shell \
        --no-create-home \
        oinit \
    && setcap cap_chown=ep /usr/bin/oinit-switch \
    && install -d -m 0750 -o oinit -g oinit /var/log/oinit \
    && install -d -m 0755 /etc/oinit

COPY configs/oinit-switch.sample.conf /etc/oinit/oinit-switch.conf
COPY container/nslcd.conf.template /etc/nslcd.conf.template
COPY container/nsswitch.files /etc/nsswitch.conf
COPY container/nsswitch.ldap /usr/share/oinit-sshd/nsswitch.ldap

# Allow the oinit user to su to provisioned (non-system) accounts; mirrors the
# oinit-openssh postinstall PAM rule.
RUN tmpf="$(mktemp)" \
    && { \
        printf '%s\n' \
            'auth [success=ignore default=1] pam_succeed_if.so use_uid user = oinit' \
            'auth sufficient                 pam_succeed_if.so uid ne 0'; \
        cat /etc/pam.d/su; \
    } > "$tmpf" \
    && chmod 0644 "$tmpf" \
    && mv "$tmpf" /etc/pam.d/su

COPY container/sshd-oinit.conf /etc/ssh/sshd_config.d/10-oinit.conf
COPY container/runit-sshd/nslcd/run /etc/sv/nslcd/run
COPY container/runit-sshd/ssh/run /etc/sv/ssh/run
RUN chmod 0755 /etc/sv/nslcd/run /etc/sv/ssh/run \
    && ln -sf /etc/sv/ssh /etc/service/ssh \
    && ln -sf /etc/sv/nslcd /etc/service/nslcd

COPY container/oinit-sshd-entrypoint.sh /usr/local/bin/oinit-sshd-entrypoint.sh
RUN chmod 0755 /usr/local/bin/oinit-sshd-entrypoint.sh

# nslcd is enabled at runtime only when /etc/nslcd.conf exists; the entrypoint
# manages the runit "down" flag and the nsswitch.conf swap.
EXPOSE 22
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["/bin/sh", "-c", "sv status /etc/service/ssh | grep -q '^run'"]
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/oinit-sshd-entrypoint.sh"]

# ---------------------------------------------------------------------------
# Client CLI (oinit add/list/match) for CI and integration testing
# ---------------------------------------------------------------------------
FROM alpine:3.20 AS oinit

RUN apk add --no-cache ca-certificates

COPY --from=builder /out/oinit /usr/bin/oinit

RUN addgroup -S oinit 2>/dev/null; \
    adduser -S oinit -H -h /var/oinit -s /sbin/nologin -G oinit 2>/dev/null; \
    install -d -m 0750 -o oinit -g oinit /var/oinit

USER oinit
ENTRYPOINT ["/usr/bin/oinit"]
