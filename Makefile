VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS = -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.date=$(DATE)

GO_BUILD = go build -trimpath -ldflags "$(LDFLAGS)"

.PHONY: build build-all release clean test lint fmt vet notices notices-check

build:
	$(GO_BUILD) -o bin/localport ./cmd/localport

build-all:
	GOOS=linux   GOARCH=amd64 $(GO_BUILD) -o bin/localport-linux-amd64       ./cmd/localport
	GOOS=linux   GOARCH=arm64 $(GO_BUILD) -o bin/localport-linux-arm64       ./cmd/localport
	GOOS=darwin  GOARCH=amd64 $(GO_BUILD) -o bin/localport-darwin-amd64      ./cmd/localport
	GOOS=darwin  GOARCH=arm64 $(GO_BUILD) -o bin/localport-darwin-arm64      ./cmd/localport
	GOOS=windows GOARCH=amd64 $(GO_BUILD) -o bin/localport-windows-amd64.exe ./cmd/localport

release: notices-check build-all
	# BSD/ISC dependencies require their notices in binary distributions, and the
	# Apache-2.0 NOTICE must travel with the software, so ship all three next to
	# the binaries.
	cp LICENSE NOTICE THIRD_PARTY_NOTICES bin/
	cd bin && { command -v sha256sum >/dev/null 2>&1 && sha256sum localport-* > checksums.txt || shasum -a 256 localport-* > checksums.txt; }

# Regenerate THIRD_PARTY_NOTICES from the module graph. Run after changing deps.
notices:
	./scripts/gen-third-party-notices.sh

# Fail if the committed notices are stale, so a dependency change cannot ship
# without its attribution. Wired into release and suitable for CI.
notices-check:
	@./scripts/gen-third-party-notices.sh
	@git diff --quiet -- THIRD_PARTY_NOTICES || { \
		echo "THIRD_PARTY_NOTICES is out of date; run 'make notices' and commit."; \
		exit 1; }

clean:
	rm -rf bin/

test:
	go test -race ./...

lint:
	golangci-lint run ./...

fmt:
	go fmt ./...
	goimports -w .

vet:
	go vet ./...
