.PHONY: build test race vet lint clean

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

clean:
	go clean
