GO := go
GOLANGCI_LINT := $(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2
GOVULNCHECK := $(GO) run golang.org/x/vuln/cmd/govulncheck@v1.8.0
ACTIONLINT := $(GO) run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
GO_FILES := $(shell find . -type f -name '*.go' -not -path './vendor/*')
CONTAINER_IMAGE ?= manhdev2002/meshtransit-core
CONTAINER_TAG ?= dev
CONTAINER_PLATFORM ?= linux/$(shell $(GO) env GOARCH)
CONTAINER_REVISION ?= unknown
TRIVY_IMAGE_FLAGS ?=
TEST_TIMEOUT ?= 2m
INTEGRATION_TEST_TIMEOUT ?= 5m
DEX_QUALIFICATION_BINARY ?=
DEX_QUALIFICATION_RELEASE ?= v2.45.1+compat.8
DEX_ARTIFACT_MANIFEST ?=
DEX_UPSTREAM_SOURCE ?=
DEX_ARTIFACT_BINARY ?=
DEX_PREPARED_ROOT ?=

.PHONY: fmt fmt-check tidy-check vet test test-race integration-deps integration-migrations integration-platform-container qualification-dex qualification-dex-boundary qualification-dex-compile qualification-dex-workspace verify-dex-artifact prepare-dex-source prepare-dex-workspace lint lint-integration vuln workflow-lint quality \
	container-build container-build-multiarch container-push-multiarch container-inspect container-smoke container-scan

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
	$(GO) test -timeout=$(TEST_TIMEOUT) -shuffle=on ./...

test-race:
	$(GO) test -timeout=$(TEST_TIMEOUT) -race -shuffle=on ./...

integration-deps:
	$(GO) test -timeout=$(INTEGRATION_TEST_TIMEOUT) -tags=integration -count=1 \
		-run '^TestTLSAuthenticatedDependencies$$' ./internal/integration

integration-migrations:
	$(GO) test -timeout=$(INTEGRATION_TEST_TIMEOUT) -tags=integration -count=1 -run '^TestPostgreSQLMigrations$$' ./internal/integration

integration-platform-container:
	bash scripts/ci/run-platform-integration.sh

qualification-dex:
	@test -n "$(DEX_QUALIFICATION_BINARY)" || { \
		echo "set DEX_QUALIFICATION_BINARY to an exact pinned Dex binary"; \
		exit 2; \
	}
	MESHTRANSIT_TEST_DEX_BINARY="$(DEX_QUALIFICATION_BINARY)" \
	MESHTRANSIT_TEST_DEX_RELEASE="$(DEX_QUALIFICATION_RELEASE)" \
	$(GO) test -timeout=$(INTEGRATION_TEST_TIMEOUT) -tags=integration -count=1 \
		-run '^TestDexBrokerCompatibilityGate$$' ./internal/integration

qualification-dex-boundary:
	$(GO) test -timeout=$(TEST_TIMEOUT) -count=1 \
		-run '^TestDexImportsConfinedToAdapter$$' ./internal/adapter/dexbroker

qualification-dex-compile:
	@test -n "$(DEX_UPSTREAM_SOURCE)" || { echo "set DEX_UPSTREAM_SOURCE"; exit 2; }
	@test -n "$(DEX_PREPARED_ROOT)" || { echo "set DEX_PREPARED_ROOT to the verified preparation directory"; exit 2; }
	$(GO) run ./tools/qualification/dexcompile \
		-upstream-source "$(DEX_UPSTREAM_SOURCE)" \
		-candidate-source "$(DEX_PREPARED_ROOT)/source"

qualification-dex-workspace:
	@test -n "$(DEX_PREPARED_ROOT)" || { echo "set DEX_PREPARED_ROOT to the verified workspace directory"; exit 2; }
	@test -f "$(DEX_PREPARED_ROOT)/go.work" || { echo "verified go.work is absent"; exit 2; }
	@test "$$(GOWORK=off $(GO) env GOVERSION)" = "go1.26.8" || { echo "Go 1.26.8 is required"; exit 1; }
	GOWORK="$(DEX_PREPARED_ROOT)/go.work" $(GO) test -timeout=$(TEST_TIMEOUT) -count=1 \
		-tags=dexbroker ./internal/adapter/dexbroker ./cmd/meshcore

verify-dex-artifact:
	@test -n "$(DEX_ARTIFACT_MANIFEST)" || { echo "set DEX_ARTIFACT_MANIFEST"; exit 2; }
	@test -n "$(DEX_UPSTREAM_SOURCE)" || { echo "set DEX_UPSTREAM_SOURCE"; exit 2; }
	@test -n "$(DEX_ARTIFACT_BINARY)" || { echo "set DEX_ARTIFACT_BINARY"; exit 2; }
	$(GO) run ./tools/qualification/dexartifact \
		-manifest "$(DEX_ARTIFACT_MANIFEST)" \
		-source "$(DEX_UPSTREAM_SOURCE)" \
		-binary "$(DEX_ARTIFACT_BINARY)"

prepare-dex-source:
	@test -n "$(DEX_ARTIFACT_MANIFEST)" || { echo "set DEX_ARTIFACT_MANIFEST"; exit 2; }
	@test -n "$(DEX_UPSTREAM_SOURCE)" || { echo "set DEX_UPSTREAM_SOURCE"; exit 2; }
	@test -n "$(DEX_ARTIFACT_BINARY)" || { echo "set DEX_ARTIFACT_BINARY"; exit 2; }
	@test -n "$(DEX_PREPARED_ROOT)" || { echo "set DEX_PREPARED_ROOT to an existing empty directory"; exit 2; }
	$(GO) run ./tools/qualification/dexartifact \
		-manifest "$(DEX_ARTIFACT_MANIFEST)" \
		-source "$(DEX_UPSTREAM_SOURCE)" \
		-binary "$(DEX_ARTIFACT_BINARY)" \
		-prepared-root "$(DEX_PREPARED_ROOT)"

prepare-dex-workspace:
	@test -n "$(DEX_ARTIFACT_MANIFEST)" || { echo "set DEX_ARTIFACT_MANIFEST"; exit 2; }
	@test -n "$(DEX_UPSTREAM_SOURCE)" || { echo "set DEX_UPSTREAM_SOURCE"; exit 2; }
	@test -n "$(DEX_ARTIFACT_BINARY)" || { echo "set DEX_ARTIFACT_BINARY"; exit 2; }
	@test -n "$(DEX_PREPARED_ROOT)" || { echo "set DEX_PREPARED_ROOT to an existing empty directory"; exit 2; }
	$(GO) run ./tools/qualification/dexartifact \
		-manifest "$(DEX_ARTIFACT_MANIFEST)" \
		-source "$(DEX_UPSTREAM_SOURCE)" \
		-binary "$(DEX_ARTIFACT_BINARY)" \
		-prepared-root "$(DEX_PREPARED_ROOT)" \
		-workspace-module "$(CURDIR)"

lint:
	$(GOLANGCI_LINT) run ./...

lint-integration:
	$(GOLANGCI_LINT) run --build-tags=integration \
		./internal/adapter/legacyts2021/protocoltest \
		./internal/integration \
		./cmd/meshcore

vuln:
	$(GOVULNCHECK) ./...

workflow-lint:
	$(ACTIONLINT)

quality: fmt-check tidy-check vet test test-race lint lint-integration vuln workflow-lint

container-build:
	docker build \
		--build-arg REVISION=$(CONTAINER_REVISION) \
		--build-arg VERSION=$(CONTAINER_TAG) \
		--platform $(CONTAINER_PLATFORM) \
		--tag $(CONTAINER_IMAGE):$(CONTAINER_TAG) \
		.

container-build-multiarch:
	docker buildx build \
		--build-arg REVISION=$(CONTAINER_REVISION) \
		--build-arg VERSION=$(CONTAINER_TAG) \
		--platform linux/amd64,linux/arm64 \
		--output type=cacheonly \
		.

container-push-multiarch:
	docker buildx build \
		--build-arg REVISION=$(CONTAINER_REVISION) \
		--build-arg VERSION=$(CONTAINER_TAG) \
		--platform linux/amd64,linux/arm64 \
		--provenance=mode=max \
		--sbom=true \
		--push \
		--tag $(CONTAINER_IMAGE):$(CONTAINER_TAG) \
		.

container-inspect:
	@test "$$(docker image inspect --format '{{.Config.User}}' $(CONTAINER_IMAGE):$(CONTAINER_TAG))" = "65532:65532"
	@test "$$(docker image inspect --format '{{json .Config.Entrypoint}}' $(CONTAINER_IMAGE):$(CONTAINER_TAG))" = '["/meshcore"]'
	@version_output="$$(docker run --rm --read-only --network=none --cap-drop=ALL \
		--security-opt=no-new-privileges $(CONTAINER_IMAGE):$(CONTAINER_TAG) version)"; \
		echo "$$version_output" | grep --fixed-strings '"version":"$(CONTAINER_TAG)"' >/dev/null; \
		echo "$$version_output" | grep --fixed-strings '"revision":"$(CONTAINER_REVISION)"' >/dev/null

container-smoke:
	@set -eu; \
		name="meshtransit-smoke-$$$$"; \
		trap 'docker rm --force "$$name" >/dev/null 2>&1 || true' EXIT; \
		docker run \
			--detach \
			--rm \
			--name "$$name" \
			--read-only \
			--cap-drop=ALL \
			--security-opt=no-new-privileges \
			--publish 127.0.0.1::8081 \
			--env MESHTRANSIT_ROLE=relay \
			--env MESHTRANSIT_HEALTH_ADDRESS=0.0.0.0:8081 \
			$(CONTAINER_IMAGE):$(CONTAINER_TAG) >/dev/null; \
		port="$$(docker port "$$name" 8081/tcp | sed 's/.*://')"; \
		attempt=0; \
	until curl --fail --silent --show-error "http://127.0.0.1:$$port/live" >/dev/null; do \
			attempt=$$((attempt + 1)); \
			test "$$attempt" -lt 40; \
			sleep 0.25; \
	done; \
	curl --fail --silent --show-error "http://127.0.0.1:$$port/ready" >/dev/null; \
	curl --fail --silent --show-error "http://127.0.0.1:$$port/metrics" \
		| grep --fixed-strings 'meshtransit_runtime_ready 1' >/dev/null

container-scan:
	trivy image $(TRIVY_IMAGE_FLAGS) \
		--exit-code 1 \
		--severity HIGH,CRITICAL \
		$(CONTAINER_IMAGE):$(CONTAINER_TAG)
