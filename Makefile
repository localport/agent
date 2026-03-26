VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS = -s -w \
	-X main.version=$(VERSION) \
	-X main.commit=$(COMMIT) \
	-X main.date=$(DATE)

GO_BUILD = go build -trimpath -ldflags "$(LDFLAGS)"

.PHONY: build build-all clean test lint fmt vet

build:
	$(GO_BUILD) -o bin/localport ./cmd/localport

build-all:
	GOOS=linux   GOARCH=amd64 $(GO_BUILD) -o bin/localport-linux-amd64       ./cmd/localport
	GOOS=linux   GOARCH=arm64 $(GO_BUILD) -o bin/localport-linux-arm64       ./cmd/localport
	GOOS=darwin  GOARCH=amd64 $(GO_BUILD) -o bin/localport-darwin-amd64      ./cmd/localport
	GOOS=darwin  GOARCH=arm64 $(GO_BUILD) -o bin/localport-darwin-arm64      ./cmd/localport
	GOOS=windows GOARCH=amd64 $(GO_BUILD) -o bin/localport-windows-amd64.exe ./cmd/localport

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
