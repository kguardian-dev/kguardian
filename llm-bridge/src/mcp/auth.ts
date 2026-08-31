import { timingSafeEqual } from "node:crypto";
import type { NextFunction, Request, RequestHandler, Response } from "express";

/**
 * Optional bearer-token auth for the MCP endpoint.
 *
 * Ported from the Broker's `broker/src/auth.rs` so both services behave the
 * same way an operator expects: unset token means no auth (the endpoint is a
 * ClusterIP-only Service by default), a set token means every request must
 * carry `Authorization: Bearer <token>` or get a 401.
 *
 * Unlike the Broker there is no probe exemption to carve out — /health lives
 * outside this router, so kubelet never reaches the bearer check.
 */

/**
 * Constant-time string comparison, the TS equivalent of the Broker's `ct_eq`.
 *
 * A naive `===` short-circuits at the first differing byte, so response
 * timing leaks how much of a guessed token was correct and an attacker can
 * recover the secret byte by byte. `crypto.timingSafeEqual` throws on
 * length-mismatched buffers, so the lengths are compared first — that check
 * leaks the token's length, which is exactly the trade-off `ct_eq` already
 * makes and is not useful without the bytes.
 */
export function tokensMatch(presented: string, expected: string): boolean {
  const a = Buffer.from(presented, "utf8");
  const b = Buffer.from(expected, "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/**
 * Extract the token from an `Authorization: Bearer <token>` header, or null
 * when the header is missing or uses another scheme. The scheme is matched
 * case-insensitively because RFC 7235 defines it that way and clients do vary
 * ("bearer" is legal); the token itself is trimmed so a trailing space in a
 * hand-written config doesn't produce a confusing 401.
 */
export function bearerTokenFrom(header: string | undefined): string | null {
  if (!header) return null;
  const match = /^Bearer\s+(.*)$/i.exec(header.trim());
  return match ? match[1].trim() : null;
}

/**
 * Express middleware enforcing the optional bearer token. `expected === null`
 * (token unset) is a pass-through, so wiring this in unconditionally is safe.
 *
 * The 401 body is deliberately uninformative — it says a bearer token is
 * required, never whether one was supplied, malformed, or merely wrong.
 */
export function requireBearer(expected: string | null): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (expected === null) {
      next();
      return;
    }
    const presented = bearerTokenFrom(req.header("authorization") ?? undefined);
    if (presented !== null && tokensMatch(presented, expected)) {
      next();
      return;
    }
    // WWW-Authenticate tells a spec-compliant MCP client which scheme to use
    // instead of leaving it to guess from a bare 401.
    res.setHeader("WWW-Authenticate", 'Bearer realm="kguardian-mcp"');
    res.status(401).json({ error: "Unauthorized", details: "A bearer token is required for this endpoint" });
  };
}
