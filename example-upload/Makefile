.PHONY: all dep build clean

all: dep build

dep:
	go mod download
build:
	go build -ldflags "-linkmode external -extldflags -static"
clean:
	go clean
	go mod tidy
