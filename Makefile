BINARY_NAME=sqleech
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-X github.com/0x6d61/sqleech/internal/cli.version=$(VERSION) -X github.com/0x6d61/sqleech/internal/cli.commit=$(COMMIT) -X github.com/0x6d61/sqleech/internal/cli.date=$(DATE)"

.PHONY: build test lint clean run vet fmt e2e-up e2e-down e2e-test e2e

build:
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/sqleech

run: build
	./bin/$(BINARY_NAME)

test:
	go test -v -count=1 ./...

test-race:
	CGO_ENABLED=1 go test -v -race -count=1 ./...

test-short:
	go test -short -count=1 ./...

test-cover:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

vet:
	go vet ./...

fmt:
	gofmt -s -w .

lint: vet
	@which staticcheck > /dev/null 2>&1 || echo "staticcheck not installed: go install honnef.co/go/tools/cmd/staticcheck@latest"
	staticcheck ./... 2>/dev/null || true

clean:
	rm -rf bin/ coverage.out coverage.html

all: fmt vet lint test build

# E2E test targets (requires Docker)
e2e-up:
	docker compose -f testenv/docker-compose.yml up -d --build --wait

e2e-down:
	docker compose -f testenv/docker-compose.yml down

e2e-test:
	go test -v -tags e2e -count=1 -timeout 120s ./e2e/...

e2e: e2e-up e2e-test e2e-down
