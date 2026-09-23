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

DIST = dist

.PHONY: build build-all dist packages repo repo-apk clean test vet-all smoke lint fmt vet notices notices-check

build:
	$(GO_BUILD) -o bin/localport ./cmd/localport

build-all:
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; \
		[ "$$os" = windows ] && ext=.exe; \
		echo "build $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch GOARM=6 $(GO_BUILD) -o bin/localport-$$os-$$arch$$ext ./cmd/localport || exit 1; \
	done

# Release set: binaries, license notices and checksums.txt.
dist: notices-check build-all
	rm -rf $(DIST)
	mkdir -p $(DIST)
	cp bin/localport-* LICENSE NOTICE THIRD_PARTY_NOTICES $(DIST)/
	./scripts/release/checksums.sh $(DIST)

# Signed Linux packages. Environment: see scripts/release/packages.sh.
packages:
	./scripts/release/packages.sh $(DIST) $(DIST)/packages

# Repository tools run in pinned images.
DEBIAN_IMAGE = debian:trixie-slim@sha256:a99cfc517144bc59b1978475ec53b46ecabec7e43635402ee5b77cc54cd1b20a
ALPINE_IMAGE = alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6
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

# `go vet` compiles test files for each platform, which a cross build skips.
vet-all:
	@for p in $(PLATFORMS); do \
		echo "vet $$p"; \
		GOOS=$${p%/*} GOARCH=$${p#*/} GOARM=6 go vet ./... || exit 1; \
	done

# Builds and runs the binary, so it is not part of `test`.
smoke:
	./scripts/smoke.sh

lint:
	golangci-lint run ./...

fmt:
	go fmt ./...
	goimports -w .

vet:
	go vet ./...
