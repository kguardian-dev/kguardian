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
 *
 * Parsed with string operations rather than the obvious `/^Bearer\s+(.*)$/i`.
 * That pattern is a polynomial ReDoS (CodeQL js/polynomial-redos): `\s+` and
 * `.` both match a space, so the two are ambiguous, and on input shaped like
 * "bearer" + many spaces + a newline — which `.` cannot cross — the engine
 * backtracks over every way of splitting the run before it can fail. This
 * function runs on an attacker-supplied header BEFORE authentication, so it
 * has to be linear no matter what it is handed.
 *
 * One deliberate difference from that regex: it rejected a token containing a
 * newline (because `.` cannot match one) and this does not. That rejection was
 * an accident of the pattern rather than a rule, an HTTP header cannot carry a
 * bare newline anyway, and the token is still compared in full by
 * `tokensMatch` — so a more permissive parse cannot authenticate anyone who
 * does not already know the secret. Tightening it instead would break an
 * operator whose token happens to contain whitespace.
 */
const BEARER_SCHEME = "bearer";

export function bearerTokenFrom(header: string | undefined): string | null {
  if (!header) return null;
  const trimmed = header.trim();
  if (trimmed.length <= BEARER_SCHEME.length) return null;
  if (trimmed.slice(0, BEARER_SCHEME.length).toLowerCase() !== BEARER_SCHEME) return null;
  const rest = trimmed.slice(BEARER_SCHEME.length);
  // RFC 7235 requires at least one space between the scheme and the token;
  // without this check "Bearerv4lu3" would authenticate as "v4lu3". Testing
  // the single leading character cannot backtrack.
  if (!/^\s/.test(rest)) return null;
  return rest.trim();
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
