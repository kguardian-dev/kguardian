# Stage 1: Build
FROM node:24-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY . .

# Build the application for production
RUN npm run build

# Stage 2: Production with serve
FROM node:24-alpine

WORKDIR /app

# Create non-root user with UID 999 to match Helm chart security context
RUN adduser -D -u 999 -s /bin/sh appuser && \
    chown -R 999:999 /app

# Install serve globally for production static file serving
RUN npm install -g serve

# Copy built assets from builder stage
COPY --from=builder --chown=999:999 /app/dist ./dist

# Switch to non-root user
USER 999

# Expose port 5173
EXPOSE 5173

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --quiet --tries=1 --spider http://localhost:5173/ || exit 1

# Serve the static files
# -s: Single-page application mode (rewrites all not-found to index.html)
# -l: Listen port
# -n: No clipboard
CMD ["serve", "-s", "dist", "-l", "5173", "-n"]
