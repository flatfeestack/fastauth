FROM golang:1.19-alpine AS base
RUN apk update && apk add --update make gcc musl-dev
WORKDIR /app
COPY go.* cache ./
RUN go mod download
#here we build cache.go, as this takes ages to compile and does not change
RUN go build && rm fastauth cache.go

FROM base as builder
COPY *.go *.sql login.html banner.txt ./
RUN go build

FROM alpine:3.17
RUN addgroup -S nonroot -g 31323 && adduser -S nonroot -G nonroot -u 31323
WORKDIR /app
COPY --from=builder /app/login.html /app/banner.txt /app/fastauth /app/rmdb.sql /app/init.sql ./
USER nonroot
ENTRYPOINT ["/app/fastauth"]
