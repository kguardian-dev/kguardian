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

# Compile vite.config.ts to plain ESM now, so the server can load it with
# vite's native loader. The default loader bundles the config at every start
# and writes the result under node_modules/.vite-temp, which needs a writable
# filesystem. Local imports are inlined; packages stay imports, resolved from
# node_modules at runtime.
RUN npx esbuild vite.config.ts --bundle --packages=external --format=esm \
  --platform=node --target=node24 --log-level=warning --outfile=vite.config.mjs

# Stage 2: only what `vite preview` loads at runtime. The app itself is
# already bundled into dist/, so of the whole dependency tree the server
# needs just vite and the React plugin the config imports. Declare those two
# as the only dependencies (at the versions package.json asks for) and let
# npm prune the installed, lockfile-resolved tree down to them: nothing is
# downloaded, and the versions stay the ones the lockfile pins.
FROM builder AS runtime-deps

RUN node -e ' \
  const fs = require("fs"); \
  const pkg = JSON.parse(fs.readFileSync("package.json", "utf8")); \
  const keep = ["vite", "@vitejs/plugin-react"]; \
  pkg.dependencies = Object.fromEntries(keep.map((k) => { \
    const v = pkg.devDependencies[k] ?? pkg.dependencies[k]; \
    if (!v) throw new Error(k + " is missing from package.json"); \
    return [k, v]; \
  })); \
  pkg.devDependencies = {}; \
  fs.writeFileSync("package.json", JSON.stringify(pkg, null, 2)); \
  ' && \
  npm prune --omit=dev --ignore-scripts --no-audit --no-fund && \
  rm -rf node_modules/.vite-temp node_modules/.vite node_modules/.cache && \
  find node_modules -mindepth 1 -maxdepth 1 -type d -empty -delete

# Stage 3: Production with Vite preview
FROM node:24-alpine

WORKDIR /app

# Create non-root user with UID 1337 to match Helm chart security context.
# npm and npx are not used at runtime; removing them drops their bundled
# dependencies from the image.
RUN adduser -D -u 1337 -s /bin/sh appuser && \
  rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx \
    /usr/local/lib/node_modules/corepack /usr/local/bin/corepack

# Built assets, the compiled config and the runtime dependencies, owned by
# root and read-only to the server: it writes nothing at runtime, so the
# container can run with a read-only root filesystem. package.json is the
# original (the config reads its version).
COPY --from=builder /app/package.json ./
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/vite.config.mjs ./
COPY --from=runtime-deps /app/node_modules ./node_modules

# Expose port 5173
EXPOSE 5173

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:5173/ || exit 1

# Switch to non-root user
USER 1337

# Use vite preview for production, with the config compiled above and
# vite's native loader (a plain import, no temp files). Bare --host (no
# address) listens on all addresses of both IP families: Node binds the IPv6
# unspecified address (accepting IPv4 as v4-mapped) and falls back to
# IPv4-only on kernels without IPv6. An explicit 0.0.0.0 is IPv4-only and
# leaves the pod unreachable on IPv6-only clusters.
CMD ["node", "node_modules/vite/bin/vite.js", "preview", "--config", "vite.config.mjs", "--configLoader", "native", "--host", "--port", "5173"]
