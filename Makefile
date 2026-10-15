GO := go
GOLANGCI_LINT := $(GO) run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.2
GOVULNCHECK := $(GO) run golang.org/x/vuln/cmd/govulncheck@v1.8.0
ACTIONLINT := $(GO) run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
GO_FILES := $(shell find core client api shared relay test -type f -name '*.go' 2>/dev/null)
VERSION ?= 0.1.0~dev
ARCH ?= amd64
CONTAINER_IMAGE ?= meshtransit/mesh-core
RELAY_IMAGE ?= meshtransit/mesh-relay
CONTAINER_TAG ?= dev
CONTAINER_PLATFORM ?= linux/$(shell $(GO) env GOARCH)
CONTAINER_REVISION ?= unknown
TRIVY_IMAGE_FLAGS ?=
TEST_TIMEOUT ?= 2m
INTEGRATION_TEST_TIMEOUT ?= 5m
DEX_QUALIFICATION_BINARY ?=
DEX_QUALIFICATION_RELEASE ?= v2.45.1+compat.9
DEX_ARTIFACT_MANIFEST ?=
DEX_UPSTREAM_SOURCE ?=
DEX_ARTIFACT_BINARY ?=
DEX_PREPARED_ROOT ?=
MOBILE_OUT ?= bin/mobile
ANDROID_API ?= 29
GOMOBILE_BIN := $(CURDIR)/bin/gomobile-tools
DEX_OLD_SOURCE ?=
DEX_CURRENT_BINARY ?=
DEX_CURRENT_BINARY_SHA256 ?=

.PHONY: test-linux-client help build build-core build-client mobile-tools mobile-android mobile-ios package-deb package-deb-meshd package-deb-meshctl package-darwin package-windows lint-client lint-relay build-relay natlab-matrix proto proto-check mtcp-crosscheck check-boundaries scan-secrets fmt fmt-check tidy-check vet test test-race integration-deps integration-migrations integration-platform-container qualification-dex qualification-dex-boundary qualification-dex-compile qualification-dex-workspace qualification-dex-upgrade-restore verify-dex-artifact prepare-dex-source prepare-dex-workspace lint lint-integration vuln workflow-lint quality \
	container-build container-build-multiarch container-push-multiarch container-push-relay-multiarch container-push-dexbroker-multiarch container-inspect container-smoke container-scan

help:
	@echo "Targets: build build-core build-client test test-race lint lint-client quality"
	@echo "         mobile-android mobile-ios"
	@echo "         check-boundaries integration-platform-container package-deb container-build"

build: build-core build-client build-relay

build-core:
	mkdir -p bin
	$(GO) build -trimpath -o bin/meshcore ./core/cmd/meshcore

build-client:
	mkdir -p bin
	$(GO) build -trimpath -o bin/meshd ./client/cmd/meshd
	$(GO) build -trimpath -o bin/meshnetd ./client/cmd/meshnetd
	$(GO) build -trimpath -o bin/meshcred ./client/cmd/meshcred
	$(GO) build -trimpath -o bin/meshctl ./client/cmd/meshctl

build-relay:
	mkdir -p bin
	$(GO) build -trimpath -o bin/meshrelay ./relay/cmd/meshrelay

# Mobile bindings of client/mobile (ADR-052), built with the gomobile and
# gobind versions pinned in go.mod. The apps consume the outputs.
mobile-tools:
	mkdir -p $(GOMOBILE_BIN)
	$(GO) build -o $(GOMOBILE_BIN)/ golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind

mobile-android: mobile-tools
	mkdir -p $(MOBILE_OUT)
	PATH="$(GOMOBILE_BIN):$$PATH" gomobile bind -trimpath -target=android/arm64,android/amd64 \
		-androidapi $(ANDROID_API) -javapkg net.meshtransit.core -o $(MOBILE_OUT)/meshcore.aar ./client/mobile

mobile-ios: mobile-tools
	mkdir -p $(MOBILE_OUT)
	PATH="$(GOMOBILE_BIN):$$PATH" gomobile bind -trimpath -target=ios \
		-prefix MT -o $(MOBILE_OUT)/MeshCore.xcframework ./client/mobile

package-deb: package-deb-meshd package-deb-meshctl

# macOS client tarballs for both architectures (unsigned).
package-darwin:
	bash packaging/darwin/build-tarball.sh "$(VERSION)" amd64 dist
	bash packaging/darwin/build-tarball.sh "$(VERSION)" arm64 dist

# Windows versions cannot carry Debian's "~" pre-release marker; 0.1.0~dev
# becomes 0.1.0-dev.
package-windows:
	bash packaging/windows/build-zip.sh "$(subst ~,-,$(VERSION))" amd64 dist
	bash packaging/windows/build-zip.sh "$(subst ~,-,$(VERSION))" arm64 dist

package-deb-meshd:
	bash packaging/linux/meshd/build-deb.sh "$(VERSION)" "$(ARCH)" dist
	bash packaging/linux/meshd/verify-deb.sh "dist/meshd_$(VERSION)_$(ARCH).deb" "$(ARCH)"

package-deb-meshctl:
	bash packaging/linux/meshctl/build-deb.sh "$(VERSION)" "$(ARCH)" dist
	bash packaging/linux/meshctl/verify-deb.sh "dist/meshctl_$(VERSION)_$(ARCH).deb" "$(ARCH)"

check-boundaries:
	bash hack/check-import-boundaries.sh
	bash hack/check-doc-links.sh

scan-secrets:
	bash hack/security/scan-secrets.sh

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

# Runs the client tests in a Linux container, so the Linux-only ones
# (identity renameat2, netadmin, netwatch, secretstore, socket, ...) run on a
# macOS workstation too. Tests that need privileges skip themselves. The
# module cache is mounted read-only and go.mod is never rewritten.
LINUX_GO_IMAGE ?= golang:1.26.9-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c
test-linux-client:
	docker run --rm -v "$(CURDIR):/src" -v "$$($(GO) env GOMODCACHE):/go/pkg/mod:ro" -w /src \
		-e GOFLAGS=-mod=readonly -e GOPROXY=off -e CGO_ENABLED=1 "$(LINUX_GO_IMAGE)" \
		go test -timeout=$(TEST_TIMEOUT) -race -count=1 ./client/... ./shared/...

integration-deps:
	$(GO) test -timeout=$(INTEGRATION_TEST_TIMEOUT) -tags=integration -count=1 \
		-run '^TestTLSAuthenticatedDependencies$$' ./core/test/integration

integration-migrations:
	$(GO) test -timeout=$(INTEGRATION_TEST_TIMEOUT) -tags=integration -count=1 -run '^TestPostgreSQLMigrations$$' ./core/test/integration

integration-platform-container:
	bash core/scripts/ci/run-platform-integration.sh

qualification-dex:
	@test -n "$(DEX_QUALIFICATION_BINARY)" || { \
		echo "set DEX_QUALIFICATION_BINARY to an exact pinned Dex binary"; \
		exit 2; \
	}
	MESHTRANSIT_TEST_DEX_BINARY="$(DEX_QUALIFICATION_BINARY)" \
	MESHTRANSIT_TEST_DEX_RELEASE="$(DEX_QUALIFICATION_RELEASE)" \
	$(GO) test -timeout=$(INTEGRATION_TEST_TIMEOUT) -tags=integration -count=1 \
		-run '^TestDexBrokerCompatibilityGate$$' ./core/test/integration

qualification-dex-boundary:
	$(GO) test -timeout=$(TEST_TIMEOUT) -count=1 \
		-run '^TestDexImportsConfinedToAdapter$$' ./core/internal/adapter/dexbroker

qualification-dex-compile:
	@test -n "$(DEX_UPSTREAM_SOURCE)" || { echo "set DEX_UPSTREAM_SOURCE"; exit 2; }
	@test -n "$(DEX_PREPARED_ROOT)" || { echo "set DEX_PREPARED_ROOT to the verified preparation directory"; exit 2; }
	$(GO) run ./core/tools/qualification/dexcompile \
		-upstream-source "$(DEX_UPSTREAM_SOURCE)" \
		-candidate-source "$(DEX_PREPARED_ROOT)/source"

qualification-dex-workspace:
	@test -n "$(DEX_PREPARED_ROOT)" || { echo "set DEX_PREPARED_ROOT to the verified workspace directory"; exit 2; }
	@toolchain="$$(bash core/scripts/qualification/check-dex-workspace.sh "$(DEX_PREPARED_ROOT)" "$(CURDIR)")" && \
	test "$$(GOWORK=off GOTOOLCHAIN="$$toolchain" $(GO) env GOVERSION)" = "$$toolchain" && \
	GOWORK="$(DEX_PREPARED_ROOT)/go.work" GOTOOLCHAIN="$$toolchain" $(GO) test -timeout=$(TEST_TIMEOUT) -count=1 \
		-tags=dexbroker ./core/internal/adapter/dexbroker ./core/cmd/meshcore

qualification-dex-upgrade-restore:
	@test -n "$(DEX_OLD_SOURCE)" || { echo "set DEX_OLD_SOURCE"; exit 2; }
	@test -n "$(DEX_PREPARED_ROOT)" || { echo "set DEX_PREPARED_ROOT"; exit 2; }
	@test -n "$(DEX_CURRENT_BINARY)" || { echo "set DEX_CURRENT_BINARY"; exit 2; }
	@test -n "$(DEX_CURRENT_BINARY_SHA256)" || { echo "set DEX_CURRENT_BINARY_SHA256"; exit 2; }
	DEX_OLD_SOURCE="$(DEX_OLD_SOURCE)" \
	DEX_PREPARED_ROOT="$(DEX_PREPARED_ROOT)" \
	DEX_CURRENT_BINARY="$(DEX_CURRENT_BINARY)" \
	DEX_CURRENT_BINARY_SHA256="$(DEX_CURRENT_BINARY_SHA256)" \
	bash core/scripts/qualification/run-identity-broker-upgrade-restore.sh

verify-dex-artifact:
	@test -n "$(DEX_ARTIFACT_MANIFEST)" || { echo "set DEX_ARTIFACT_MANIFEST"; exit 2; }
	@test -n "$(DEX_UPSTREAM_SOURCE)" || { echo "set DEX_UPSTREAM_SOURCE"; exit 2; }
	@test -n "$(DEX_ARTIFACT_BINARY)" || { echo "set DEX_ARTIFACT_BINARY"; exit 2; }
	$(GO) run ./core/tools/qualification/dexartifact \
		-manifest "$(DEX_ARTIFACT_MANIFEST)" \
		-source "$(DEX_UPSTREAM_SOURCE)" \
		-binary "$(DEX_ARTIFACT_BINARY)"

prepare-dex-source:
	@test -n "$(DEX_ARTIFACT_MANIFEST)" || { echo "set DEX_ARTIFACT_MANIFEST"; exit 2; }
	@test -n "$(DEX_UPSTREAM_SOURCE)" || { echo "set DEX_UPSTREAM_SOURCE"; exit 2; }
	@test -n "$(DEX_ARTIFACT_BINARY)" || { echo "set DEX_ARTIFACT_BINARY"; exit 2; }
	@test -n "$(DEX_PREPARED_ROOT)" || { echo "set DEX_PREPARED_ROOT to an existing empty directory"; exit 2; }
	$(GO) run ./core/tools/qualification/dexartifact \
		-manifest "$(DEX_ARTIFACT_MANIFEST)" \
		-source "$(DEX_UPSTREAM_SOURCE)" \
		-binary "$(DEX_ARTIFACT_BINARY)" \
		-prepared-root "$(DEX_PREPARED_ROOT)"

prepare-dex-workspace:
	@test -n "$(DEX_ARTIFACT_MANIFEST)" || { echo "set DEX_ARTIFACT_MANIFEST"; exit 2; }
	@test -n "$(DEX_UPSTREAM_SOURCE)" || { echo "set DEX_UPSTREAM_SOURCE"; exit 2; }
	@test -n "$(DEX_ARTIFACT_BINARY)" || { echo "set DEX_ARTIFACT_BINARY"; exit 2; }
	@test -n "$(DEX_PREPARED_ROOT)" || { echo "set DEX_PREPARED_ROOT to an existing empty directory"; exit 2; }
	$(GO) run ./core/tools/qualification/dexartifact \
		-manifest "$(DEX_ARTIFACT_MANIFEST)" \
		-source "$(DEX_UPSTREAM_SOURCE)" \
		-binary "$(DEX_ARTIFACT_BINARY)" \
		-prepared-root "$(DEX_PREPARED_ROOT)" \
		-workspace-module "$(CURDIR)"

lint:
	$(GOLANGCI_LINT) run ./core/... ./api/...

lint-client:
	$(GOLANGCI_LINT) run --config client/.golangci.yml ./client/... ./shared/... ./test/...

# Regenerates test/natlab/testdata/matrix.md; review the diff before committing.
lint-relay:
	$(GOLANGCI_LINT) run --config relay/.golangci.yml ./relay/...

natlab-matrix:
	$(GO) test ./test/natlab -run TestTraversalMatrix -count=1 -update

# Regenerates the Go code of api/ protobuf schemas without protoc
# (hack/protogen); proto-check fails when the committed code is stale.
proto:
	$(GO) run -C hack/protogen . ../../api mtcp/v1/mtcp.proto

proto-check: proto
	git diff --exit-code -- api/

# Recomputes shared/mtcp/testdata/vectors.json with an independent
# implementation (needs Python 3 with the cryptography package).
mtcp-crosscheck:
	python3 shared/mtcp/testdata/crosscheck.py shared/mtcp/testdata/vectors.json

lint-integration:
	$(GOLANGCI_LINT) run --build-tags=integration \
		./core/internal/adapter/mtcp/mtcptest \
		./core/test/integration \
		./core/cmd/meshcore

vuln:
	$(GOVULNCHECK) ./...

workflow-lint:
	$(ACTIONLINT)

quality: fmt-check tidy-check vet test test-race lint lint-integration vuln workflow-lint check-boundaries

container-build:
	docker build \
		--build-arg REVISION=$(CONTAINER_REVISION) \
		--build-arg VERSION=$(CONTAINER_TAG) \
		--platform $(CONTAINER_PLATFORM) \
		--file core/Dockerfile \
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
		--file core/Dockerfile \
		--tag $(CONTAINER_IMAGE):$(CONTAINER_TAG) \
		.

container-push-relay-multiarch:
	docker buildx build \
		--build-arg REVISION=$(CONTAINER_REVISION) \
		--build-arg VERSION=$(CONTAINER_TAG) \
		--platform linux/amd64,linux/arm64 \
		--provenance=mode=max \
		--sbom=true \
		--push \
		--file relay/Dockerfile \
		--tag $(RELAY_IMAGE):$(CONTAINER_TAG) \
		.

container-push-dexbroker-multiarch:
	@test -n "$(DEX_PREPARED_ROOT)" || { echo "set DEX_PREPARED_ROOT to the verified workspace directory"; exit 2; }
	@test -f "$(DEX_PREPARED_ROOT)/go.work" || { echo "verified go.work is absent"; exit 2; }
	@test -f "$(DEX_PREPARED_ROOT)/source/go.mod" || { echo "verified Dex root module is absent"; exit 2; }
	@test -f "$(DEX_PREPARED_ROOT)/source/api/v2/go.mod" || { echo "verified Dex API module is absent"; exit 2; }
	docker buildx build \
		--build-context "dex=$(DEX_PREPARED_ROOT)/source" \
		--build-arg REVISION=$(CONTAINER_REVISION) \
		--build-arg VERSION=$(CONTAINER_TAG) \
		--file core/Dockerfile.dexbroker \
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
