# syntax=docker/dockerfile:1
#
# Official image, built from the verified release binaries.
#
#   docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 \
#     -f packaging/Dockerfile dist/
#
# Credentials are stored in /home/nonroot/.localport.

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG TARGETARCH
ARG VERSION
ARG REVISION
ARG CREATED

LABEL org.opencontainers.image.title="localport" \
      org.opencontainers.image.description="Localport agent: tunnels and remote access" \
      org.opencontainers.image.url="https://localport.io" \
      org.opencontainers.image.documentation="https://localport.io/docs" \
      org.opencontainers.image.source="https://github.com/localport/agent" \
      org.opencontainers.image.vendor="Localport" \
      org.opencontainers.image.authors="Localport <support@localport.io>" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}" \
      org.opencontainers.image.created="${CREATED}"

COPY --chmod=0755 localport-linux-${TARGETARCH} /usr/bin/localport
COPY LICENSE NOTICE THIRD_PARTY_NOTICES /usr/share/doc/localport/

ENV LOCALPORT_HOME=/home/nonroot/.localport
USER nonroot:nonroot
ENTRYPOINT ["/usr/bin/localport"]
