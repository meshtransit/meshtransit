GO := go
GOLANGCI_LINT := $(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2
GOVULNCHECK := $(GO) run golang.org/x/vuln/cmd/govulncheck@v1.8.0
GO_FILES := $(shell find . -type f -name '*.go' -not -path './vendor/*')

.PHONY: fmt fmt-check tidy-check vet test test-race lint vuln quality

fmt:
	gofmt -w $(GO_FILES)

fmt-check:
	@unformatted="$$(gofmt -l $(GO_FILES))"; \
		test -z "$$unformatted" || { echo "unformatted Go files:"; echo "$$unformatted"; exit 1; }

tidy-check:
	$(GO) mod tidy -diff

vet:
	$(GO) vet ./...

test:
	$(GO) test -shuffle=on ./...

test-race:
	$(GO) test -race -shuffle=on ./...

lint:
	$(GOLANGCI_LINT) run ./...

vuln:
	$(GOVULNCHECK) ./...

quality: fmt-check tidy-check vet test test-race lint vuln
