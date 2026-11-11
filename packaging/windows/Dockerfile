# The Windows packaging check image: NSIS 3.13 makensis built from its source
# release (SHA-256 pinned) with the mingw-w64 cross compiler for its Windows
# stubs and plugins, the manifest schemas at pinned commits, and the Debian
# JSON Schema validator. `make check-packaging` builds and runs it.
# SourceForge publishes no checksum for NSIS; NSIS_SRC_SHA256 is the SHA-256
# of the official download, and the release workflow pins the Windows zip
# the same way. Bump all pins together with a new NSIS release.
FROM debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a

ARG NSIS_VERSION=3.13
ARG NSIS_SRC_SHA256=a8ffe024602d46b6d766f9e1ce30c324ad2a24daeacd3efc2642d436a0c157ac
ARG WINGET_CLI_COMMIT=dafe5e7795c6b36e2a8cea86aa9fddec898df795
ARG SCOOP_COMMIT=79669717fe3e53ba642ec073a45bbe53acb77b8e

RUN apt-get update -qq \
	&& DEBIAN_FRONTEND=noninteractive apt-get install -qq -y --no-install-recommends \
		ca-certificates curl bzip2 scons g++ zlib1g-dev mingw-w64 \
		python3 python3-yaml python3-jsonschema=4.19.2-6 \
	&& rm -rf /var/lib/apt/lists/*

# makensis for Linux and the x86-unicode stubs and stock plugins (System,
# nsExec) for Windows; no utilities or documentation.
RUN curl -fsSL -o /tmp/nsis.tar.bz2 \
		"https://downloads.sourceforge.net/project/nsis/NSIS%203/${NSIS_VERSION}/nsis-${NSIS_VERSION}-src.tar.bz2" \
	&& echo "${NSIS_SRC_SHA256}  /tmp/nsis.tar.bz2" | sha256sum -c - \
	&& mkdir /tmp/nsis && tar -xjf /tmp/nsis.tar.bz2 -C /tmp/nsis --strip-components=1 \
	&& cd /tmp/nsis \
	&& scons -j"$(nproc)" XGCC_W32_PREFIX=i686-w64-mingw32- SKIPUTILS=all SKIPMISC=all SKIPDOC=all DOCTYPES=none \
		NSIS_CONFIG_CONST_DATA_PATH=yes PREFIX=/opt/nsis install \
	&& rm -rf /tmp/nsis /tmp/nsis.tar.bz2

RUN mkdir -p /schemas/winget \
	&& for f in version installer defaultLocale; do \
		curl -fsSL -o "/schemas/winget/manifest.${f}.1.28.0.json" \
			"https://raw.githubusercontent.com/microsoft/winget-cli/${WINGET_CLI_COMMIT}/schemas/JSON/manifests/v1.28.0/manifest.${f}.1.28.0.json"; \
	done \
	&& curl -fsSL -o /schemas/scoop.json \
		"https://raw.githubusercontent.com/ScoopInstaller/Scoop/${SCOOP_COMMIT}/schema.json"

ENV PATH=/opt/nsis/bin:$PATH
