.PHONY: test build vet
test:
	go test ./...
vet:
	go vet ./...
build:
	go build -o bin/avd ./cmd/avd
	go build -o bin/av ./cmd/av
