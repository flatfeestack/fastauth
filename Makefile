#Execute the following commands:
# 'make' and it will create the binary
# 'make clean' ant it will remove the binary
NAME:=fastauth

.PHONY: all test build clean dep

all: dep build test
test:
	go test ./... -v
build:
	go build -o $(NAME)
dep: go.mod
	go mod tidy
	go get -v -u ./...
clean:
	go clean
	rm -f $(NAME)
go.mod:
	go mod init $(NAME)
