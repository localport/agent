# syntax=docker/dockerfile:1
# Builds localport-session (cgo) for one Linux platform. Build context: the
# agent module root. Driven by `make build-session-linux` in CI:
#
#   docker buildx build --platform linux/<arch> -f packaging/session/Dockerfile \
#     --build-arg TOOLCHAIN=<stage> --build-arg TAGS=<tags> \
#     --build-arg NAME=<output name> --build-arg LDFLAGS=<flags> \
#     --output type=local,dest=bin .
#
# Toolchain stages:
#   glibc-el8   AlmaLinux 8: glibc 2.28 floor (RHEL/Rocky 8, Debian 10, Ubuntu 20.04), amd64 and arm64
#   musl        Alpine 3.24: musl, with or without linux-pam (TAGS=pam or empty)
# The 32-bit ARM glibc build uses the ARMv6 cross toolchain instead
# (`make build-session-armv6`).

ARG TOOLCHAIN

FROM golang:1.27.3-bookworm@sha256:d9b6a1beb9474adc2a1ce842573639b44b2a0dd49b6669f51d3821baf9ec37c9 AS go

FROM almalinux:8.10@sha256:2d0f2eb2a83cc09dbc2eb92fade4dbe8f709628149e81aa00aec70630406603b AS glibc-el8
RUN dnf -y -q install gcc pam-devel binutils && dnf clean all
COPY --from=go /usr/local/go /usr/local/go
ENV GLIBC_FLOOR=2.28

FROM golang:1.27.3-alpine3.24@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb AS musl
RUN apk add -q --no-cache gcc musl-dev linux-pam-dev binutils

FROM ${TOOLCHAIN} AS build
ENV PATH=/usr/local/go/bin:$PATH CGO_ENABLED=1 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TAGS
ARG LDFLAGS
RUN go build -trimpath -buildvcs=false -tags "$TAGS" -ldflags "$LDFLAGS" \
	-o /out/localport-session ./cmd/localport-session
RUN packaging/session/check.sh /out/localport-session "$TAGS" "${GLIBC_FLOOR:-}"

FROM scratch
ARG NAME
COPY --from=build /out/localport-session /${NAME}
