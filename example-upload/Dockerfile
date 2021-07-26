FROM golang:1.16-alpine AS base
RUN apk update && apk add --update make gcc musl-dev
WORKDIR /app
COPY *.go go.* Makefile ./
#here we build cache.go, as this takes ages to compile and does not change
RUN make

