# syntax=docker/dockerfile:1.29.0@sha256:572cebbc2b15e6f84c077742952674889cb63cd5e9b80abdffcbe587b6f19183
# Toolchain images for the cgo localport-session builds: gcc, the PAM
# headers, binutils and git, each at an exact version. Go is not included.
# .github/workflows/session-builder.yml builds each stage, signs it and pushes
# it as ghcr.io/localport/session-builder:<stage>. A push to main that changes
# this file runs that workflow.
#
# Stages:
#   glibc-el8   AlmaLinux 8.10 (glibc 2.28), linux/amd64 and linux/arm64
#   musl        Alpine 3.24, linux/amd64, linux/arm64 and linux/arm/v6

FROM almalinux:8.10@sha256:2d0f2eb2a83cc09dbc2eb92fade4dbe8f709628149e81aa00aec70630406603b AS glibc-el8
RUN dnf -y -q install \
		gcc-8.5.0-31.el8_10.alma.1 \
		pam-devel-1.3.1-40.el8_10 \
		binutils-2.30-128.el8_10 \
		git-2.43.7-1.el8_10 && \
	dnf clean all

FROM alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS musl
RUN apk add -q --no-cache \
		gcc=15.2.0-r5 \
		musl-dev=1.2.6-r3 \
		linux-pam-dev=1.7.1-r2 \
		binutils=2.45.1-r1 \
		git=2.54.1-r0
