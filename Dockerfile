FROM golang:1.15-alpine AS builder
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
RUN apk add make gcc musl-dev
WORKDIR /app
COPY . .
RUN chown -R appuser:appgroup /app
USER appuser
RUN make

FROM alpine:3.12
RUN addgroup -S appgroup && adduser -S appuser -G appgroup
WORKDIR /app
COPY --from=builder /app/banner.txt /app/fastauth /app/startup.sql ./
RUN chown -R appuser:appgroup /app
USER appuser
ENTRYPOINT ["./fastauth"]
