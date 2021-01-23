FROM golang:1.15-alpine AS builder
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
RUN apk add make gcc musl-dev
WORKDIR /app
RUN chown -R appuser:appgroup /app
USER appuser
# User from here
COPY --chown=appuser:appgroup go.* Makefile ./
RUN --mount=type=cache,target=/root/.cache/go-build make dep
COPY --chown=appuser:appgroup . .
RUN --mount=type=cache,target=/root/.cache/go-build make build test

FROM alpine:3.13
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
WORKDIR /app
COPY --from=builder /app/login.html /app/banner.txt /app/fastauth /app/startup.sql ./
RUN chown -R appuser:appgroup /app
USER appuser
ENTRYPOINT ["./fastauth"]
