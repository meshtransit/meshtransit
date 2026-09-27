.PHONY: build test control-integration control-registration-integration race vet lint scan-secrets audit-release package-deb audit-deb clean

VERSION ?= 0.1.0~dev
ARCH ?= amd64

build:
	mkdir -p bin
	go build -trimpath -o bin/meshd ./cmd/meshd
	go build -trimpath -o bin/meshnetd ./cmd/meshnetd

test:
	go test ./...

control-integration:
	go test -tags=integration -run '^TestClient_ProbeLiveControl$$' ./internal/compat/ts2021

control-registration-integration:
	go test -tags=integration -run '^TestClient_RegisterAndReceiveInitialMap$$' ./internal/compat/ts2021

race:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

scan-secrets:
	bash tools/security/scan-secrets.sh

audit-release: build
	bash tools/security/audit-release-binary.sh bin/meshd bin/meshnetd

package-deb:
	bash packaging/linux/build-deb.sh "$(VERSION)" "$(ARCH)" dist
	bash packaging/linux/verify-deb.sh "dist/meshd_$(VERSION)_$(ARCH).deb" "$(ARCH)"

audit-deb:
	bash tools/security/audit-linux-package.sh "dist/meshd_$(VERSION)_$(ARCH).deb"

clean:
	go clean
