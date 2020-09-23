FROM golang:1.14 AS builder
WORKDIR /app
COPY . .
RUN make

FROM alpine:latest
WORKDIR /app
COPY --from=builder /app/fastauth .
CMD ["./fastauth"]
