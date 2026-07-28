# syntax=docker/dockerfile:1

# gomod-vex supports two modes with different runtime needs:
#   * image mode -> skopeo + govulncheck (no Go toolchain required)
#   * repo mode  -> git + a Go toolchain (govulncheck source analysis)
# The runtime image ships all of them so both modes work out of the box.

ARG GO_VERSION=1.25

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION}-bookworm AS build
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0
WORKDIR /src

# Cache modules first (gomod-vex has no external deps, so this is just go.mod).
COPY go.mod ./
RUN go mod download

COPY . .
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/gomod-vex .

# Build govulncheck with the SAME Go version so source-mode package loading does
# not hit a toolchain / x-tools version mismatch.
RUN mkdir /tmp/gv && cd /tmp/gv \
    && go mod init govulncheck-build >/dev/null \
    && go get golang.org/x/vuln/cmd/govulncheck@latest \
    && GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" \
       -o /out/govulncheck golang.org/x/vuln/cmd/govulncheck

# Runtime: Go toolchain (repo mode) + git + skopeo (image mode) + the binaries.
FROM golang:${GO_VERSION}-bookworm
RUN apt-get update \
    && apt-get install -y --no-install-recommends skopeo git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/gomod-vex /usr/local/bin/gomod-vex
COPY --from=build /out/govulncheck /usr/local/bin/govulncheck

LABEL org.opencontainers.image.source="https://github.com/cwayne18/gomod-vex" \
      org.opencontainers.image.description="Check whether Go-module CVEs are actually present/exploitable in a container image or source repo" \
      org.opencontainers.image.licenses="MIT"

ENTRYPOINT ["gomod-vex"]
