.PHONY: all dep build test clean

all: dep build test

dep:
	go mod download
build:
	go build -ldflags "-linkmode external -extldflags -static"
test:
	go test
clean:
	go clean
	go mod tidy
