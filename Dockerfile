FROM golang:1.14-alpine AS builder
WORKDIR /app
RUN apk add make gcc musl-dev
COPY . .
RUN make

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/banner.txt /app/fastauth /app/startup.sql ./
CMD ["./fastauth"]
