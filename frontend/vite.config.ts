import { defineConfig, type ProxyOptions } from 'vite'
import react from '@vitejs/plugin-react'
import { readFileSync } from 'fs'

const pkg = JSON.parse(readFileSync('./package.json', 'utf-8'))

/**
 * The Authorization value the /api proxy presents to the broker, or
 * undefined when BROKER_AUTH_TOKEN is unset. The chart mounts the
 * broker's `read` token here. It is read on the server at runtime and
 * never reaches the browser bundle (only VITE_* variables are bundled).
 */
export function brokerAuthHeader(env: NodeJS.ProcessEnv = process.env): string | undefined {
  const token = env.BROKER_AUTH_TOKEN?.trim()
  return token ? `Bearer ${token}` : undefined
}

interface HeaderSink {
  removeHeader(name: string): void
  setHeader(name: string, value: string): void
}

/**
 * Rewrite the Authorization header of a proxied broker request. Whatever
 * the browser sent is dropped first: behind an SSO proxy (oauth2-proxy
 * with pass_authorization_header) that header is the user's ID token,
 * which has no business reaching the broker. Then the server-held read
 * token is set, when configured.
 */
export function applyBrokerAuth(req: HeaderSink, authHeader: string | undefined): void {
  req.removeHeader('authorization')
  if (authHeader) req.setHeader('authorization', authHeader)
}

/** One path segment: unreserved characters plus `:` and `@` (IPv6
 * addresses in /pod/ip/{ip}). No `%`, so no encoded slash, dot or
 * double-encoding can reach the broker, whose router would decode it. */
const SEGMENT = /^[A-Za-z0-9._~:@-]+$/
/** The one POST the UI makes: the seccomp profile export (a read that
 * carries its options in a body). */
const EXPORT_POST = /^\/seccomp\/profiles\/[^/]+\/[^/]+\/[^/]+\/export$/

export type ProxyDecision =
  | { allow: true }
  | { allow: false; status: 400 | 405; reason: string }

/**
 * Whether the /api proxy forwards a request. The proxy holds a broker
 * token, so it only forwards what the UI actually does: GET and HEAD
 * anywhere, and POST only to the seccomp export. Everything else is
 * refused here with 405 and never forwarded. The broker's own scope check
 * stays the real boundary; this keeps the proxy from being a
 * general-purpose authenticated client for anyone who can reach it (and,
 * in `shared` token mode, from writing).
 *
 * `url` is the request URL with or without the /api prefix, query allowed.
 */
export function brokerProxyDecision(method: string | undefined, url: string | undefined): ProxyDecision {
  const raw = (url ?? '').split('?')[0].split('#')[0]
  const path = raw.replace(/^\/api(?=\/|$)/, '') || '/'
  const segments = path.split('/').slice(1)
  const pathOk =
    path.startsWith('/') &&
    !path.includes('\\') &&
    segments.every((s, i) => (s === '' ? i === segments.length - 1 : SEGMENT.test(s) && s !== '.' && s !== '..'))
  if (!pathOk) {
    return { allow: false, status: 400, reason: 'path contains encoded or unsupported characters' }
  }
  const m = (method ?? '').toUpperCase()
  if (m === 'GET' || m === 'HEAD') return { allow: true }
  if (m === 'POST' && EXPORT_POST.test(path)) return { allow: true }
  return { allow: false, status: 405, reason: `${m || 'this method'} is not allowed through the broker proxy` }
}

interface BypassRequest {
  method?: string
  url?: string
}
interface BypassResponse {
  statusCode: number
  setHeader(name: string, value: string): unknown
  end(body?: string): unknown
}

/**
 * vite `bypass` hook: answers a refused request itself and stops it.
 * Returning a string after ending the response is how vite's proxy
 * middleware is told "handled, don't forward" (it checks writableEnded).
 */
export function refuseDisallowed(req: BypassRequest, res: BypassResponse | undefined): string | false | undefined {
  const d = brokerProxyDecision(req.method, req.url)
  if (d.allow) return undefined
  if (!res) return false // websocket upgrade: vite answers 404
  res.statusCode = d.status
  if (d.status === 405) res.setHeader('Allow', 'GET, HEAD, POST')
  res.setHeader('Content-Type', 'text/plain')
  res.end(d.reason)
  return req.url ?? '/'
}

/** The /api → broker proxy shared by the dev server and vite preview. */
export function brokerProxy(env: NodeJS.ProcessEnv = process.env): ProxyOptions {
  const authHeader = brokerAuthHeader(env)
  return {
    target: env.VITE_API_URL || 'http://localhost:9090',
    changeOrigin: true,
    rewrite: (path) => path.replace(/^\/api/, ''),
    bypass: (req, res) => refuseDisallowed(req, res),
    configure: (proxy) => {
      proxy.on('proxyReq', (proxyReq, req) => {
        // Second line of defence: never attach the token to a request the
        // allowlist refuses, even if the bypass hook were skipped.
        const ok = brokerProxyDecision(req.method, req.url).allow
        applyBrokerAuth(proxyReq, ok ? authHeader : undefined)
      })
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],

  define: {
    __APP_VERSION__: JSON.stringify(pkg.version),
  },

  // Development server configuration
  server: {
    allowedHosts: true,
    proxy: {
      '/api': brokerProxy(),
      '/llm-api': {
        target: process.env.VITE_LLM_BRIDGE_URL || 'http://localhost:8080',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/llm-api/, ''),
      },
    },
  },

  // Production build configuration
  build: {
    // Output directory for production build
    outDir: 'dist',

    // Generate sourcemaps for production debugging (optional, disable for smaller builds)
    sourcemap: false,

    // Target modern browsers for smaller bundles
    target: 'esnext',

    // Optimize chunk splitting
    rollupOptions: {
      output: {
        manualChunks: (id) => {
          if (id.includes('node_modules/react/') || id.includes('node_modules/react-dom/')) {
            return 'react-vendor'
          }
          if (id.includes('node_modules/reactflow/') || id.includes('node_modules/@reactflow/')) {
            return 'react-flow-vendor'
          }
        },
      },
    },

    // Chunk size warning limit (500 KB)
    chunkSizeWarningLimit: 500,

    // Minification
    minify: 'esbuild',

    // Asset optimization
    assetsInlineLimit: 4096, // 4kb - inline assets smaller than this
  },

  // Preview server configuration (for production)
  preview: {
    port: 5173,
    // true, not '0.0.0.0': listen on all addresses of BOTH families.
    // Node then binds the IPv6 unspecified address (accepting IPv4 as
    // v4-mapped) and falls back to IPv4-only on kernels without IPv6 —
    // a literal '0.0.0.0' never accepts connections on the pod's IPv6
    // address, so probes and Service traffic fail on IPv6-only clusters.
    host: true,
    strictPort: true,
    allowedHosts: true,
    proxy: {
      '/api': brokerProxy(),
      '/llm-api': {
        target: process.env.VITE_LLM_BRIDGE_URL || 'http://localhost:8080',
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/llm-api/, ''),
      },
    },
  },
})
