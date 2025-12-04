# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git make gcc musl-dev

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build binaries
RUN CGO_ENABLED=1 go build -o /nexus ./cmd/nexus
RUN CGO_ENABLED=0 go build -o /nexusctl ./cmd/nexusctl

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 nexus && \
    adduser -u 1000 -G nexus -s /bin/sh -D nexus

# Create data directories
RUN mkdir -p /var/lib/nexus/data/keys && \
    chown -R nexus:nexus /var/lib/nexus

# Copy binaries
COPY --from=builder /nexus /usr/local/bin/nexus
COPY --from=builder /nexusctl /usr/local/bin/nexusctl

USER nexus
WORKDIR /var/lib/nexus

EXPOSE 9000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost:9000/health || exit 1

ENTRYPOINT ["nexus"]
CMD ["-addr", ":9000", "-storage", "sqlite", "-db", "/var/lib/nexus/nexus.db"]
