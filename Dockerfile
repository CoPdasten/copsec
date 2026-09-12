# Multi-stage Dockerfile for CoPSeC Controller
FROM golang:1.24-alpine AS builder

WORKDIR /build

# Install build dependencies
RUN apk add --no-cache git build-base

# Copy dependency files
COPY go.mod go.sum ./
RUN go mod download

# Copy source tree
COPY . .

# Build Controller and CLI
RUN CGO_ENABLED=1 GOOS=linux go build -ldflags="-s -w" -o /build/copsec-controller ./controller
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /build/copsec ./cmd/copsec

# Runtime Stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata sqlite curl bash

WORKDIR /app

# Create standard directories
RUN mkdir -p /etc/copsec/rules /var/lib/copsec /var/log/copsec

# Copy compiled binaries
COPY --from=builder /build/copsec-controller /usr/local/bin/copsec-controller
COPY --from=builder /build/copsec /usr/local/bin/copsec

# Copy rules
COPY rules/ /etc/copsec/rules/

EXPOSE 8080 50051

VOLUME ["/var/lib/copsec", "/etc/copsec"]

ENTRYPOINT ["/usr/local/bin/copsec-controller"]
CMD ["--db-path=/var/lib/copsec/vault.db", "--grpc-port=50051", "--port=8080"]
