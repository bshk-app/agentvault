.PHONY: test cross-test build vet

# VERSION is injected into BOTH binaries via -ldflags so `av version` reports a real
# build tag; it defaults to the git describe (or "dev" without git). The release
# Formula/Cask override it with the release tag.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

test:
	go test ./...
cross-test:
	GOOS=linux GOARCH=amd64 go test -exec=/usr/bin/true ./...
	GOOS=windows GOARCH=amd64 go test -exec=/usr/bin/true ./...
vet:
	go vet ./...
build:
	go build -ldflags "-X main.version=$(VERSION)" -o bin/avd ./cmd/avd
	go build -ldflags "-X main.version=$(VERSION)" -o bin/av ./cmd/av
