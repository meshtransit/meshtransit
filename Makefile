.PHONY: build test race vet lint package-deb clean

VERSION ?= 0.1.0~dev
ARCH ?= amd64

build:
	mkdir -p bin
	go build -trimpath -o bin/meshctl ./cmd/meshctl

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

package-deb:
	bash packaging/linux/build-deb.sh "$(VERSION)" "$(ARCH)" dist
	bash packaging/linux/verify-deb.sh "dist/meshctl_$(VERSION)_$(ARCH).deb" "$(ARCH)"

clean:
	go clean
