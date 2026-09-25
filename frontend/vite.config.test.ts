import { EventEmitter } from 'node:events'
import { describe, expect, it } from 'vitest'
import { applyBrokerAuth, brokerAuthHeader, brokerProxy, brokerProxyDecision, refuseDisallowed } from './vite.config'

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
