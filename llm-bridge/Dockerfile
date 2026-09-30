FROM node:24-alpine AS builder

WORKDIR /app

# Copy package files and TypeScript config
COPY package*.json tsconfig.json ./

# Install dependencies
RUN npm ci

# Copy source code
COPY src ./src

# Build TypeScript
RUN npm run build

# Production stage
FROM node:24-alpine

WORKDIR /app

# Copy package files and install production dependencies only. npm, npx
# and corepack are not used at runtime (the server is started with node);
# removing them once the install is done drops the base image's bundled npm
# dependencies, and their CVEs, from the image.
COPY package*.json ./
RUN npm ci --only=production && \
  rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx \
    /usr/local/lib/node_modules/corepack /usr/local/bin/corepack

# Copy built application from builder
COPY --from=builder /app/dist ./dist

# Set environment variables
ENV NODE_ENV=production
ENV PORT=8080
ENV BROKER_URL=http://broker.kguardian.svc.cluster.local:9090

# Expose port
EXPOSE 8080

# Run as non-root user
USER node

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "require('http').get('http://localhost:8080/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Start the server
CMD ["node", "dist/index.js"]
