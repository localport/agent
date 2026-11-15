VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)

# The build date is the commit time, so builds are reproducible.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || date +%s)
DATE := $(shell date -u -d @$(SOURCE_DATE_EPOCH) +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || \
	date -u -r $(SOURCE_DATE_EPOCH) +%Y-%m-%dT%H:%M:%SZ)

# Release builds set BUILDVCS=true to fail without a git checkout.
BUILDVCS ?= auto

LDFLAGS = -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.date=$(DATE)

GO_BUILD = CGO_ENABLED=0 go build -trimpath -buildvcs=$(BUILDVCS) -ldflags "$(LDFLAGS)"

# Release platforms. linux/arm targets ARMv6 and also runs on ARMv7.
PLATFORMS = linux/amd64 linux/arm64 linux/arm darwin/amd64 darwin/arm64 windows/amd64

# localport-session links libpam through cgo, so it is built per platform, in
# CI only (.github/workflows/session.yml): Linux in Docker
# (packaging/session/Dockerfile, buildx with QEMU for non-native platforms),
# 32-bit ARM glibc with the ARMv6 cross toolchain, darwin natively on macOS.
# The agent stays static.
# Docker entries: <docker platform>:<toolchain stage>:<build tags>:<name suffix>.
# glibc builds need glibc 2.28 (amd64, arm64) or 2.36 (ARMv6); musl builds run
# on Alpine (armhf is ARMv6); the build without tags has no PAM.
SESSION_LINUX = \
	linux/amd64:glibc-el8:pam:linux_amd64 \
	linux/arm64:glibc-el8:pam:linux_arm64 \
	linux/amd64:musl:pam:linux_amd64_musl \
	linux/arm64:musl:pam:linux_arm64_musl \
	linux/arm/v6:musl:pam:linux_arm_musl \
	linux/amd64:musl::linux_amd64_musl_nopam \
	linux/arm64:musl::linux_arm64_musl_nopam \
	linux/arm/v6:musl::linux_arm_musl_nopam
SESSION_DARWIN = amd64 arm64
SESSION_NAMES = $(foreach e,$(SESSION_LINUX),localport-session_$(lastword $(subst :, ,$(e)))) \
	localport-session_linux_arm \
	$(foreach a,$(SESSION_DARWIN),localport-session_darwin_$(a))

# ARMv6 hard-float glibc toolchain and libpam sysroot, made by
# packaging/session/armv6/toolchain.sh.
ARMV6_TOOLCHAIN ?= $(HOME)/x-tools-localport
ARMV6_TARGET = armv6-rpi-linux-gnueabihf
ARMV6_GLIBC_FLOOR = 2.36

# darwin release binaries: built and ad-hoc signed with the hardened runtime
# on macOS (`make build-darwin`); `dist` on Linux takes them from bin/.
DARWIN_NAMES = $(foreach a,$(SESSION_DARWIN),localport-darwin-$(a) localport-session_darwin_$(a))

DIST = dist

.PHONY: winres check-packaging build build-all build-session-linux build-session-armv6 build-session-darwin build-darwin sign-darwin dist release-sign release-dryrun packages repo repo-apk clean test test-root vet-all smoke lint errwrapcheck fmt vet notices notices-check cargo-deny

build:
	$(GO_BUILD) -o bin/localport ./cmd/localport

build-all: winres
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; \
		[ "$$os" = windows ] && ext=.exe; \
		echo "build $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch GOARM=6 $(GO_BUILD) -o bin/localport-$$os-$$arch$$ext ./cmd/localport || exit 1; \
		if [ "$$os" = windows ]; then \
			GOOS=$$os GOARCH=$$arch $(GO_BUILD) -o bin/localport-session-$$os-$$arch$$ext ./cmd/localport-session || exit 1; \
		fi; \
	done

# VERSIONINFO resources of the Windows executables; see scripts/release/winres.sh.
winres:
	@./scripts/release/winres.sh '$(VERSION)'

# Compiles the Windows installer (both NSIS passes) and validates the Scoop
# and winget manifests against their pinned schemas in the packaging image
# (packaging/windows/Dockerfile). Needs Docker.
check-packaging:
	./scripts/release/check-packaging.sh

# The Docker builds in SESSION_LINUX; CI runs one entry per job by setting
# SESSION_LINUX. The git directory and the common directory are separate build
# contexts (a submodule's .git is a file pointing outside the module; a
# worktree's git directory holds only its own HEAD and index), mounted only
# while go build stamps the VCS information, so BUILDVCS means the same as for
# the other builds. In a plain checkout both are the same directory.
build-session-linux:
	@gitdir="$$(git rev-parse --absolute-git-dir)" && \
	commondir="$$(git rev-parse --path-format=absolute --git-common-dir)" || { echo "build-session-linux needs a git checkout"; exit 1; }; \
	for e in $(SESSION_LINUX); do \
		IFS=:; set -- $$e; IFS=' '; \
		echo "build localport-session_$$4"; \
		docker buildx build --quiet --platform "$$1" -f packaging/session/Dockerfile \
			--build-context git="$$gitdir" --build-context gitcommon="$$commondir" \
			--build-arg TOOLCHAIN="$$2" --build-arg TAGS="$$3" --build-arg BUILDVCS="$(BUILDVCS)" \
			--build-arg NAME="localport-session_$$4" --build-arg "LDFLAGS=$(LDFLAGS)" \
			--output type=local,dest=bin . || exit 1; \
	done

# 32-bit ARM glibc build for ARMv6 hard float (Raspberry Pi OS on Pi Zero and
# Pi 1). Debian's armhf compiler emits ARMv7 code, so this uses its own toolchain.
build-session-armv6:
	@cc=$(ARMV6_TOOLCHAIN)/$(ARMV6_TARGET)/bin/$(ARMV6_TARGET)-gcc; pam=$(ARMV6_TOOLCHAIN)/pam; \
	[ -x "$$cc" ] || { echo "no ARMv6 toolchain; run packaging/session/armv6/toolchain.sh $(ARMV6_TOOLCHAIN)"; exit 1; }; \
	echo "build localport-session_linux_arm"; \
	CC="$$cc" CGO_ENABLED=1 GOOS=linux GOARCH=arm GOARM=6 \
		CGO_CFLAGS="-O2 -I$$pam/usr/include" \
		CGO_LDFLAGS="-L$$pam/usr/lib/arm-linux-gnueabihf -Wl,-rpath-link,$$pam/lib/arm-linux-gnueabihf" \
		go build -trimpath -buildvcs=$(BUILDVCS) -tags pam -ldflags "$(LDFLAGS)" \
		-o bin/localport-session_linux_arm ./cmd/localport-session && \
	READELF="$${cc%gcc}readelf" OBJDUMP="$${cc%gcc}objdump" \
		packaging/session/check.sh bin/localport-session_linux_arm pam $(ARMV6_GLIBC_FLOOR) v6

build-session-darwin:
	@[ "$$(uname -s)" = Darwin ] || { echo "build-session-darwin needs macOS"; exit 1; }
	@for arch in $(SESSION_DARWIN); do \
		echo "build localport-session_darwin_$$arch"; \
		MACOSX_DEPLOYMENT_TARGET=13.0 CGO_ENABLED=1 GOOS=darwin GOARCH=$$arch \
			go build -trimpath -buildvcs=$(BUILDVCS) -tags pam -ldflags "$(LDFLAGS)" \
			-o bin/localport-session_darwin_$$arch ./cmd/localport-session || exit 1; \
	done

# Both darwin binaries of the release, ad-hoc signed with the hardened runtime.
build-darwin: build-session-darwin
	@$(MAKE) --no-print-directory build-all PLATFORMS="$(filter darwin/%,$(PLATFORMS))"
	@$(MAKE) --no-print-directory sign-darwin

# Ad-hoc signature (no Developer ID) with the hardened runtime and a fixed
# identifier, io.localport.<binary name>.
sign-darwin:
	@[ "$$(uname -s)" = Darwin ] || { echo "sign-darwin needs macOS"; exit 1; }
	@for f in $(DARWIN_NAMES); do \
		name=$${f%_darwin_*}; name=$${name%-darwin-*}; \
		codesign --force --sign - --options runtime --identifier "io.localport.$$name" bin/$$f && \
		codesign --verify --strict bin/$$f && \
		codesign --display --verbose=1 bin/$$f 2>&1 | grep -Eq '^CodeDirectory .*flags=0x[0-9a-f]+\([^)]*runtime' || \
		{ echo "bin/$$f: signature check failed"; exit 1; }; \
		echo "signed bin/$$f as io.localport.$$name"; \
	done

# Release set: binaries, license notices and checksums.txt. The release
# workflow builds the localport-session binaries and the signed darwin
# binaries in other jobs and puts them in bin/ first; dist builds the rest.
dist: notices-check
	@$(MAKE) --no-print-directory build-all PLATFORMS="$(filter-out darwin/%,$(PLATFORMS))"
	@for f in $(SESSION_NAMES) $(DARWIN_NAMES); do \
		[ -f bin/$$f ] || { echo "bin/$$f is missing"; exit 1; }; \
	done
	rm -rf $(DIST)
	mkdir -p $(DIST)
	cp bin/localport-* LICENSE NOTICE THIRD_PARTY_NOTICES $(DIST)/
	./scripts/release/checksums.sh $(DIST)

# Verifies and signs a draft release. Maintainer only; see RELEASING.md.
release-sign:
	@[ -n "$(TAG)" ] || { echo "usage: make release-sign TAG=vX.Y.Z"; exit 1; }
	./scripts/release/sign.sh "$(TAG)"

# Full release pipeline with throwaway keys, including install tests.
# Publishes nothing.
release-dryrun:
	./scripts/release/dryrun.sh

# Signed Linux packages. Environment: see scripts/release/packages.sh.
packages:
	./scripts/release/packages.sh $(DIST) $(DIST)/packages

# Repository tools run in pinned images.
DEBIAN_IMAGE = debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2
ALPINE_IMAGE = alpine:3.24@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
HOST_IDS := $(shell id -u):$(shell id -g)

# apt and rpm repositories in $(DIST)/repo. Needs REPO_GPG_KEY_FILE.
repo:
	@[ -s "$(REPO_GPG_KEY_FILE)" ] || { echo "REPO_GPG_KEY_FILE must name the repository signing key"; exit 1; }
	docker run --rm \
		-v "$(CURDIR):/src" -w /src \
		-v "$(abspath $(dir $(REPO_GPG_KEY_FILE))):/keys:ro" \
		-e REPO_GPG_KEY_FILE=/keys/$(notdir $(REPO_GPG_KEY_FILE)) \
		-e REPO_GPG_PASSPHRASE -e KEEP -e DEBIAN_FRONTEND=noninteractive \
		$(DEBIAN_IMAGE) sh -euc '\
			apt-get update -qq; \
			apt-get install -qq -y --no-install-recommends apt-utils createrepo-c rpm gnupg >/dev/null; \
			trap "chown -R $(HOST_IDS) $(DIST)/repo" EXIT; \
			scripts/release/repo.sh $(DIST)/packages $(DIST)/repo'

# Alpine repository in $(DIST)/repo. Needs APK_KEY_FILE.
repo-apk:
	@[ -s "$(APK_KEY_FILE)" ] || { echo "APK_KEY_FILE must name the apk signing key"; exit 1; }
	docker run --rm \
		-v "$(CURDIR):/src" -w /src \
		-v "$(abspath $(dir $(APK_KEY_FILE))):/keys:ro" \
		-e APK_KEY_FILE=/keys/$(notdir $(APK_KEY_FILE)) \
		-e KEYS_DIR -e KEEP \
		$(ALPINE_IMAGE) sh -euc '\
			apk add -q --no-cache abuild coreutils; \
			trap "chown -R $(HOST_IDS) $(DIST)/repo" EXIT; \
			scripts/release/repo-apk.sh $(DIST)/packages $(DIST)/repo'

# Regenerate THIRD_PARTY_NOTICES from the module graph. Run after changing deps.
notices:
	./scripts/gen-third-party-notices.sh

# Fail if the committed notices are stale, so a dependency change cannot ship
# without its attribution. Wired into dist and suitable for CI.
notices-check:
	@./scripts/gen-third-party-notices.sh
	@git diff --quiet -- THIRD_PARTY_NOTICES || { \
		echo "THIRD_PARTY_NOTICES is out of date; run 'make notices' and commit."; \
		exit 1; }

clean:
	rm -rf bin/ $(DIST)/

test:
	go test -race ./...
	go -C tools/errwrapcheck test ./...

# The tests that need euid 0. Each is named TestRoot... and skips without root,
# so `test` runs none of them unprivileged. The pam tag needs the libpam
# headers (libpam0g-dev, pam-devel or linux-pam-dev).
TEST_ROOT_TAGS ?= pam
test-root:
	go test -race -count=1 -v -tags "$(TEST_ROOT_TAGS)" -run '^TestRoot' ./...

# `go vet` compiles test files for each platform, which a cross build skips.
vet-all:
	@for p in $(PLATFORMS); do \
		echo "vet $$p"; \
		GOOS=$${p%/*} GOARCH=$${p#*/} GOARM=6 go vet ./... || exit 1; \
	done

# RustSec advisories for the Rust golden generators of the RDP tests, each
# against its own deny.toml. Needs cargo-deny (RELEASING.md "Maintenance").
CARGO_FIXTURES = internal/session/testdata/rdpfilter internal/session/testdata/rdcleanpath
cargo-deny:
	@for d in $(CARGO_FIXTURES); do \
		echo "cargo deny $$d"; \
		cargo deny --manifest-path $$d/Cargo.toml --config $$d/deny.toml check advisories || exit 1; \
	done

# Builds and runs the binary, so it is not part of `test`.
smoke:
	./scripts/smoke.sh

lint: errwrapcheck
	golangci-lint run ./...

# errwrapcheck (tools/errwrapcheck, its own module) runs as a vet tool per
# platform, since build tags select different files.
errwrapcheck:
	go -C tools/errwrapcheck build -o $(CURDIR)/bin/errwrapcheck .
	@for p in $(PLATFORMS); do \
		GOOS=$${p%/*} GOARCH=$${p#*/} GOARM=6 go vet -vettool=$(CURDIR)/bin/errwrapcheck ./... || exit 1; \
	done

fmt:
	go fmt ./...
	goimports -w .

vet:
	go vet ./...
