FROM golang:1.16-alpine AS base
WORKDIR /app
RUN apk add --no-cache make gcc musl-dev
COPY go.* Makefile cache ./
#here we build cache.go, as this takes ages to compile and does not change
RUN make dep && make build && rm fastauth cache.go

FROM base as builder
COPY *.go *.sql *.html *.txt ./
RUN make build test

FROM gcr.io/distroless/static
WORKDIR /app
COPY --from=builder /app/login.html /app/banner.txt /app/fastauth /app/rmdb.sql /app/init.sql ./
ENTRYPOINT ["/app/fastauth"]
