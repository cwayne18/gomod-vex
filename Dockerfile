# syntax=docker/dockerfile:1

# Build stage: cross-compile gomod-vex and govulncheck for the target platform.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
ARG TARGETOS
ARG TARGETARCH
ENV CGO_ENABLED=0
WORKDIR /src

# Download modules first for better layer caching. gomod-vex has no external
# dependencies, so this is just go.mod.
COPY go.mod ./
RUN go mod download

COPY . .
RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/gomod-vex .

# Build govulncheck in an isolated module so it never touches gomod-vex's go.mod.
RUN mkdir /tmp/gv && cd /tmp/gv \
    && go mod init govulncheck-build >/dev/null \
    && go get golang.org/x/vuln/cmd/govulncheck@latest \
    && GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" \
       -o /out/govulncheck golang.org/x/vuln/cmd/govulncheck

# Runtime stage: skopeo (image pull/flatten) plus the two static binaries.
FROM alpine:3.21
RUN apk add --no-cache skopeo ca-certificates
COPY --from=build /out/gomod-vex /usr/local/bin/gomod-vex
COPY --from=build /out/govulncheck /usr/local/bin/govulncheck

LABEL org.opencontainers.image.source="https://github.com/cwayne18/gomod-vex" \
      org.opencontainers.image.description="Check whether Go-module CVEs are actually present/exploitable in a container image's binaries" \
      org.opencontainers.image.licenses="MIT"

ENTRYPOINT ["gomod-vex"]
