BINARY := buildtrace
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: bootstrap build test race golden lint fmt vet run manifest docker clean

bootstrap:
	go mod download
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) ./cmd/buildtrace


test:
	go test -count=1 ./...

race:
	go test -race -count=1 ./...

# Regenerates the golden manifest. The ordinary test run compares against it
# and never rewrites it.
golden:
	BUILDTRACE_WRITE_GOLDEN=1 go test ./internal/manifest -run TestWriteTheGoldenFile -count=1

lint: fmt vet
	golangci-lint run ./...

fmt:
	gofmt -l -w .

vet:
	go vet ./...

run: build
	./bin/$(BINARY)

# Writes a manifest for the artifacts named on the command line:
#   make manifest ARTIFACTS="dist/app dist/app.sig"
manifest: build
	./bin/$(BINARY) manifest $(foreach a,$(ARTIFACTS),--artifact $(a)) --out buildtrace.json

docker:
	docker build -t buildtrace:$(VERSION) .

clean:
	go clean
	rm -rf bin
