.PHONY: build test race vet lint clean

build:
	mkdir -p bin
	go build -trimpath -o bin/meshd ./cmd/meshd
	go build -trimpath -o bin/meshnetd ./cmd/meshnetd

test:
	go test ./...

race:
	go test -race ./...

vet:
	go vet ./...

lint:
	golangci-lint run ./...

clean:
	go clean
