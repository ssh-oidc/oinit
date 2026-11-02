# syntax=docker/dockerfile:1.7

# Legacy source build for oinit-ca (make oinit-ca-docker).
#
# The canonical, feature-complete image set lives at container/Dockerfile;
# prefer:
#   docker build -f container/Dockerfile --target oinit-ca -t sshoidc/oinit-ca .

FROM golang:1.24-alpine AS builder

WORKDIR /build
COPY . /build
# Build the package, not a single file, so subpackages stay intact.
RUN CGO_ENABLED=0 go build -trimpath \
        -ldflags="-s -w -X main.version=$(cat VERSION 2>/dev/null || echo dev)" \
        -o /out/oinit-ca ./cmd/oinit-ca

FROM alpine:3.20

WORKDIR /app
COPY --from=builder /out/oinit-ca /usr/bin/oinit-ca

# Config and key material live here; mount a volume over it in practice.
RUN mkdir -p -m 0750 /etc/oinit

# The listen address comes from `listen-address` in the config file; pass
# `-l host:port` to override it.
ENTRYPOINT ["/usr/bin/oinit-ca"]
CMD ["-c", "/etc/oinit/ca-config.ini"]
