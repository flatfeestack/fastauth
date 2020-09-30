FROM golang:1.14-alpine AS builder
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
WORKDIR /app
RUN apk add make gcc musl-dev
COPY . .
RUN make

FROM alpine:latest
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
WORKDIR /app
COPY --from=builder /app/banner.txt /app/fastauth /app/startup.sql ./
ENTRYPOINT ["./fastauth"]
