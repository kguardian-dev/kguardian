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

# Stage 2: Production with Vite preview
FROM node:24-alpine

WORKDIR /app

# Create non-root user with UID 1337 to match Helm chart security context
RUN adduser -D -u 1337 -s /bin/sh appuser && \
  chown -R 1337:1337 /app

# Copy package files and built assets from builder stage
COPY --from=builder --chown=1337:1337 /app/package*.json ./
COPY --from=builder --chown=1337:1337 /app/dist ./dist

# Install only production dependencies (includes vite for preview)
RUN npm ci --omit=dev

# Switch to non-root user
USER 1337

# Expose port 5173
EXPOSE 5173

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:5173/ || exit 1

# Use vite preview to serve the static files
# Vite preview automatically serves SPA with proper routing
CMD ["npm", "run", "preview", "--", "--host", "0.0.0.0", "--port", "5173"]
