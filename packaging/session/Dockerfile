# syntax=docker/dockerfile:1.29.0@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183
# Builds localport-session (cgo) for one Linux platform. Build context: the
# agent module root. Driven by `make build-session-linux` in CI:
#
#   docker buildx build --platform linux/<arch> -f packaging/session/Dockerfile \
#     --build-arg TOOLCHAIN=<stage> --build-arg TAGS=<tags> \
#     --build-arg NAME=<output name> --build-arg LDFLAGS=<flags> \
#     --output type=local,dest=bin .
#
# Toolchain stages, each a signed builder image (packaging/session/builder.Dockerfile)
# plus Go from the official image:
#   glibc-el8   AlmaLinux 8: glibc 2.28 floor (RHEL/Rocky 8, Debian 10, Ubuntu 20.04), amd64 and arm64
#   musl        Alpine 3.24: musl, with or without linux-pam (TAGS=pam or empty)
# The 32-bit ARM glibc build uses the ARMv6 cross toolchain instead
# (`make build-session-armv6`). session.yml verifies the builder image
# signatures before it builds.

ARG TOOLCHAIN

FROM golang:1.27.4-bookworm@sha256:4fa7c968ba93f1635670522dbb01a2c78150443e1385746924566079f36570ea AS go-glibc

FROM golang:1.27.4-alpine3.24@sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf AS go-musl

FROM ghcr.io/localport/session-builder:glibc-el8@sha256:b069bffe183ecb08029093617c92d1d0a0ce607e50e26bbed15a82b91031c4ba AS glibc-el8
COPY --from=go-glibc /usr/local/go /usr/local/go
ENV GLIBC_FLOOR=2.28

FROM ghcr.io/localport/session-builder:musl@sha256:79dcf681a4d29822f02ef9ada91bd8bdc5e29a086930ac9d836efa88319522bf AS musl
COPY --from=go-musl /usr/local/go /usr/local/go

FROM ${TOOLCHAIN} AS build
ENV PATH=/usr/local/go/bin:$PATH CGO_ENABLED=1 GOTOOLCHAIN=local GOFLAGS=-mod=readonly
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TAGS
ARG LDFLAGS
ARG BUILDVCS=auto
# The git directory (build context "git") is mounted for the build only, so
# the binary carries the same VCS stamp as the other release builds and no
# layer holds the repository. GIT_WORK_TREE overrides a submodule's
# core.worktree; the files belong to the host user, hence safe.directory.
RUN --mount=type=bind,from=git,target=/src/.git \
	GIT_WORK_TREE=/src GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0=/src \
	go build -trimpath -buildvcs="$BUILDVCS" -tags "$TAGS" -ldflags "$LDFLAGS" \
	-o /out/localport-session ./cmd/localport-session
RUN packaging/session/check.sh /out/localport-session "$TAGS" "${GLIBC_FLOOR:-}"

FROM scratch
ARG NAME
COPY --from=build /out/localport-session /${NAME}
