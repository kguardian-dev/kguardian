FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go module files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY main.go ./
COPY tools ./tools

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o kguardian-mcp .

# Production stage
FROM alpine:latest

WORKDIR /app

# Install ca-certificates for HTTPS requests
RUN apk --no-cache add ca-certificates

# Copy built application from builder
COPY --from=builder /app/kguardian-mcp .

# Set environment variables
ENV BROKER_URL=http://broker.kguardian.svc.cluster.local:9090
ENV PORT=8081

# Create non-root user
RUN addgroup -g 1000 mcp && \
    adduser -D -u 1000 -G mcp mcp

# Run as non-root user
USER mcp

# Expose port
EXPOSE 8081

# Start the MCP server
CMD ["./kguardian-mcp"]
