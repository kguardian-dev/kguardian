import { EventEmitter } from 'node:events'
import { describe, expect, it } from 'vitest'
import { createServer } from 'vite'
import config, {
  allowedHostsFromEnv, applyBrokerAuth, brokerAuthHeader, brokerProxy, brokerProxyDecision, llmProxy, llmProxyDecision,
  refuseDisallowed, SECURITY_HEADERS,
} from './vite.config'

class FakeProxyReq {
  headers = new Map<string, string>()
  removeHeader(name: string) {
    this.headers.delete(name.toLowerCase())
  }
  setHeader(name: string, value: string) {
    this.headers.set(name.toLowerCase(), value)
  }
}

describe('broker proxy auth', () => {
  it('reads the token from BROKER_AUTH_TOKEN, treating blank as unset', () => {
    expect(brokerAuthHeader({ BROKER_AUTH_TOKEN: ' tok ' })).toBe('Bearer tok')
    expect(brokerAuthHeader({ BROKER_AUTH_TOKEN: '   ' })).toBeUndefined()
    expect(brokerAuthHeader({})).toBeUndefined()
  })

  it('replaces a browser-supplied Authorization header with the read token', () => {
    const req = new FakeProxyReq()
    req.setHeader('Authorization', 'Bearer sso-id-token')
    applyBrokerAuth(req, 'Bearer read-token')
    expect(req.headers.get('authorization')).toBe('Bearer read-token')
  })

  it('strips a browser-supplied Authorization header when no token is configured', () => {
    const req = new FakeProxyReq()
    req.setHeader('Authorization', 'Bearer sso-id-token')
    applyBrokerAuth(req, undefined)
    expect(req.headers.has('authorization')).toBe(false)
  })

  it('wires the header onto allowed proxied requests only', () => {
    const opts = brokerProxy({ BROKER_AUTH_TOKEN: 'read-token', VITE_API_URL: 'http://broker:9090' })
    expect(opts.target).toBe('http://broker:9090')
    expect(opts.rewrite?.('/api/pod/info')).toBe('/pod/info')
    const proxy = new EventEmitter()
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    opts.configure?.(proxy as any, opts)

    const allowed = new FakeProxyReq()
    proxy.emit('proxyReq', allowed, { method: 'GET', url: '/pod/info' })
    expect(allowed.headers.get('authorization')).toBe('Bearer read-token')

    const refused = new FakeProxyReq()
    refused.setHeader('Authorization', 'Bearer smuggled')
    proxy.emit('proxyReq', refused, { method: 'POST', url: '/pod/mark_dead' })
    expect(refused.headers.has('authorization')).toBe(false)
  })
})

describe('broker proxy allowlist', () => {
  const allowedCases: [string, string][] = [
    ['GET', '/api/pod/info'],
    ['GET', '/api/pod/traffic/web-1?limit=10'],
    ['GET', '/api/pod/ip/fd00::1?at=2026-09-26T00:00:00Z'],
    ['HEAD', '/api/version'],
    ['get', '/api/seccomp/profiles'],
    ['GET', '/api/compute/history/1b4e28ba-2fa1-11d2-883f-0016d3cca427'],
    ['POST', '/api/seccomp/profiles/prod/Deployment/web/export'],
  ]
  it.each(allowedCases)('forwards %s %s', (method, url) => {
    expect(brokerProxyDecision(method, url)).toEqual({ allow: true })
  })

  const methodRefused: [string, string][] = [
    ['POST', '/api/pod/mark_dead'],
    ['POST', '/api/pod/traffic/batch'],
    ['POST', '/api/node/facts'],
    ['POST', '/api/seccomp/denials'],
    ['POST', '/api/seccomp/node-status'],
    ['PUT', '/api/seccomp/crs/a/b'],
    ['DELETE', '/api/seccomp/crs/a/b'],
    ['PATCH', '/api/pod/info'],
    ['OPTIONS', '/api/pod/info'],
    ['POST', '/api/seccomp/profiles/prod/Deployment/web/export/extra'],
    ['POST', '/api/seccomp/profiles/prod/Deployment/export'],
  ]
  it.each(methodRefused)('refuses %s %s with 405', (method, url) => {
    expect(brokerProxyDecision(method, url)).toMatchObject({ allow: false, status: 405 })
  })

  const pathRefused: [string, string][] = [
    ['POST', '/api/pod/traffic/%62atch'],
    ['POST', '/api/pod/mark%5Fdead'],
    ['POST', '/api/pod/mark%5fdead'],
    ['GET', '/api/pod/traffic%2Fbatch'],
    ['GET', '/api/pod/traffic%2fbatch'],
    ['GET', '/api/pod/traffic/%2562atch'],
    ['GET', '/api/../health'],
    ['GET', '/api/pod/./info'],
    ['GET', '/api/pod//info'],
    ['GET', '/api/pod\\info'],
    ['POST', '/api/seccomp/profiles/prod/Deployment/w%65b/export'],
  ]
  it.each(pathRefused)('refuses %s %s with 400 (encoded or unnormalised path)', (method, url) => {
    expect(brokerProxyDecision(method, url)).toMatchObject({ allow: false, status: 400 })
  })

  it('answers a refused request itself and tells vite not to forward', () => {
    const res = { statusCode: 200, headers: {} as Record<string, string>, body: '', ended: false,
      setHeader(n: string, v: string) { this.headers[n] = v },
      end(b?: string) { this.body = b ?? ''; this.ended = true } }
    const out = refuseDisallowed({ method: 'POST', url: '/api/pod/mark_dead' }, res)
    expect(res.statusCode).toBe(405)
    expect(res.headers.Allow).toBe('GET, HEAD, POST')
    expect(res.ended).toBe(true)
    expect(typeof out).toBe('string')

    const pass = { ...res, statusCode: 200, ended: false }
    expect(refuseDisallowed({ method: 'GET', url: '/api/pod/info' }, pass)).toBeUndefined()
    expect(pass.ended).toBe(false)

    expect(refuseDisallowed({ method: 'POST', url: '/api/pod/mark_dead' }, undefined)).toBe(false)
  })
})

describe('allowed hosts', () => {
  it('reads a comma-separated ALLOWED_HOSTS, trimmed and lowercased', () => {
    expect(allowedHostsFromEnv({ ALLOWED_HOSTS: ' KGuardian.example.com , kguardian-frontend,,kguardian-frontend.kguardian.svc ' }))
      .toEqual(['kguardian.example.com', 'kguardian-frontend', 'kguardian-frontend.kguardian.svc'])
  })

  it('turns an ingress wildcard into vite\'s subdomain form', () => {
    expect(allowedHostsFromEnv({ ALLOWED_HOSTS: '*.example.com' })).toEqual(['.example.com'])
  })

  it('stays permissive when ALLOWED_HOSTS is unset or blank, so existing installs keep working', () => {
    expect(allowedHostsFromEnv({})).toBe(true)
    expect(allowedHostsFromEnv({ ALLOWED_HOSTS: ' , ' })).toBe(true)
  })

  it('is what both the dev server and vite preview use', () => {
    // The config module is evaluated with the test process's env, where ALLOWED_HOSTS is unset.
    expect(config.server?.allowedHosts).toEqual(allowedHostsFromEnv())
    expect(config.preview?.allowedHosts).toEqual(allowedHostsFromEnv())
  })
})

describe('security headers', () => {
  it('vite preview sends them on every response', () => {
    expect(config.preview?.headers).toEqual(SECURITY_HEADERS)
  })

  it('refuse framing and sniffing, and load images only from the app itself', () => {
    expect(SECURITY_HEADERS['X-Content-Type-Options']).toBe('nosniff')
    expect(SECURITY_HEADERS['X-Frame-Options']).toBe('DENY')
    const csp = SECURITY_HEADERS['Content-Security-Policy']
    expect(csp).toContain("frame-ancestors 'none'")
    expect(csp).toContain("img-src 'self' data:")
    expect(csp).toContain("script-src 'self'")
    expect(csp).not.toMatch(/script-src[^;]*unsafe/)
  })
})

describe('llm-bridge proxy', () => {
  it('forwards only the chat stream the UI posts to', () => {
    expect(llmProxyDecision('POST', '/llm-api/api/chat/stream')).toEqual({ allow: true })
    expect(llmProxyDecision('POST', '/llm-api/api/chat/stream?x=1')).toEqual({ allow: true })
    expect(llmProxyDecision('GET', '/llm-api/health')).toEqual({ allow: true })
    expect(llmProxyDecision('GET', '/llm-api/api/chat/stream')).toMatchObject({ allow: false, status: 405 })
    expect(llmProxyDecision('POST', '/llm-api/mcp')).toMatchObject({ allow: false, status: 404 })
    expect(llmProxyDecision('POST', '/llm-api/api/chat')).toMatchObject({ allow: false, status: 404 })
    expect(llmProxyDecision('POST', '/llm-api/api/chat/stream/../../mcp')).toMatchObject({ allow: false, status: 404 })
  })

  it('answers a refused request itself', () => {
    const opts = llmProxy({ VITE_LLM_BRIDGE_URL: 'http://bridge:8080' })
    expect(opts.target).toBe('http://bridge:8080')
    expect(opts.rewrite?.('/llm-api/api/chat/stream')).toBe('/api/chat/stream')
    const res = { statusCode: 200, headers: {} as Record<string, string>, body: '', ended: false,
      setHeader(n: string, v: string) { this.headers[n] = v },
      end(b?: string) { this.body = b ?? ''; this.ended = true } }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const out = opts.bypass?.({ method: 'POST', url: '/llm-api/mcp' } as any, res as any, opts)
    expect(res.statusCode).toBe(404)
    expect(res.ended).toBe(true)
    expect(typeof out).toBe('string')
  })

  it('never passes the browser\'s Authorization header (an SSO ID token behind oauth2-proxy) to the bridge', () => {
    const opts = llmProxy({})
    const proxy = new EventEmitter()
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    opts.configure?.(proxy as any, opts)
    const req = new FakeProxyReq()
    req.setHeader('Authorization', 'Bearer sso-id-token')
    proxy.emit('proxyReq', req, { method: 'POST', url: '/llm-api/api/chat/stream' })
    expect(req.headers.has('authorization')).toBe(false)
  })
})

// With SSO, the gateway routes /oauth2/* to oauth2-proxy, so a request for
// /oauth2/userinfo that reaches this server means nothing is in front of it.
// It used to fall through to a 404 (the SPA fallback serves HTML requests
// only), a console error on every page load of an install without SSO.
describe('SSO user info without a proxy in front', () => {
  it('answers /oauth2/userinfo with 204 No Content, not a 404', async () => {
    const server = await createServer({ configFile: './vite.config.ts', logLevel: 'silent', server: { port: 0, strictPort: false } })
    await server.listen()
    try {
      const base = server.resolvedUrls!.local[0]
      const res = await fetch(new URL('/oauth2/userinfo', base), { headers: { Accept: 'application/json' } })
      expect(res.status).toBe(204)
      expect(res.headers.get('cache-control')).toBe('no-store')
      expect(res.headers.get('x-kguardian-sso')).toBe('none')
      expect(await res.text()).toBe('')
      // Only that path: the rest of /oauth2/ is the proxy's, never answered here.
      expect((await fetch(new URL('/oauth2/sign_out', base), { headers: { Accept: 'application/json' } })).status).not.toBe(204)
    } finally {
      await server.close()
    }
  }, 20_000)
})
