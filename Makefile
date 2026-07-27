.PHONY: test cross-test build vet

# VERSION is injected into EVERY binary via -ldflags so `av version` reports a real
# build tag; it defaults to the git describe (or "dev" without git). The release
# Formula/Cask override it with the release tag.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# `go build -o <path>` writes exactly <path> — the toolchain does NOT append .exe when
# -o names a file. That is load-bearing for the plugin: age locates it with
# exec.LookPath, which on Windows only accepts a PATHEXT extension, so an extensionless
# age-plugin-av is invisible to age (and surfaces as "no identity matched", not as a
# missing file). GOEXE is empty off Windows, so this is a no-op on macOS/Linux.
EXE := $(shell go env GOEXE)

test:
	go test ./...
cross-test:
	GOOS=linux GOARCH=amd64 go test -exec=/usr/bin/true ./...
	GOOS=windows GOARCH=amd64 go test -exec=/usr/bin/true ./...
vet:
	go vet ./...
build:
	go build -ldflags "-X main.version=$(VERSION)" -o bin/avd$(EXE) ./cmd/avd
	go build -ldflags "-X main.version=$(VERSION)" -o bin/av$(EXE) ./cmd/av
	go build -ldflags "-X main.version=$(VERSION)" -o bin/age-plugin-av$(EXE) ./cmd/age-plugin-av
