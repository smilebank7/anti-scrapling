.PHONY: build test test-race lint e2e js-bundle docker clean help

BIN_DIR := bin
GO := go
NPM := npm
# Allow Go toolchain auto-download for deps requiring newer Go
export GOTOOLCHAIN ?= auto

help:
	@echo "Targets: build test test-race lint e2e js-bundle docker clean"

build:
	$(GO) build -o $(BIN_DIR)/antiscrapling ./cmd/antiscrapling
	$(GO) build -o $(BIN_DIR)/antiscrapling-cli ./cmd/antiscrapling-cli

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

lint:
	@command -v golangci-lint >/dev/null 2>&1 || { echo "Install golangci-lint: https://golangci-lint.run"; exit 1; }
	golangci-lint run ./...

js-bundle:
	@cd web/challenge && $(NPM) install --silent && $(NPM) run build

e2e:
	@echo "E2E tests run via docker-compose; see tests/scrapling/"
	@cd tests/scrapling && docker compose up --abort-on-container-exit --build

docker:
	docker build -f deploy/docker/Dockerfile -t anti-scrapling:dev .

testdata-refresh:
	@echo "See testdata/_tools/refresh.sh"
	@bash testdata/_tools/refresh.sh || true

clean:
	rm -rf $(BIN_DIR)
