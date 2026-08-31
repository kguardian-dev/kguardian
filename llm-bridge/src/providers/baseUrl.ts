/**
 * Endpoint resolution shared by every provider.
 *
 * Each provider used to hard-code its endpoint, which made the assistant
 * unusable against anything but the vendor's own API. Operators run
 * OpenAI-compatible gateways (LiteLLM, vLLM, an enterprise proxy) in front of
 * whatever model they actually want, so the host has to be configurable while
 * the request path stays owned by the provider implementation.
 *
 * The rule, uniform across providers: the env var carries a BASE, and the
 * provider appends its own request path to it VERBATIM. kguardian never
 * inserts, removes, or rewrites a `/v1` segment.
 *
 * That last part is deliberate and is the sharp edge here. LiteLLM answers on
 * both `/chat/completions` and `/v1/chat/completions`, so operators set the
 * base with and without `/v1` and both appear to "work" — but vLLM and most
 * other gateways serve only the `/v1` form. Any rule that guesses (append a
 * missing `/v1`, or strip a duplicate one) would silently rewrite a URL the
 * operator deliberately chose and would break the gateways that expose only
 * one of the two. Appending verbatim is also exactly what the OpenAI SDK does
 * with OPENAI_BASE_URL, so a value copy-pasted from another tool's config
 * behaves identically here. When the base is wrong the answer is a clear
 * error (see `endpointHint`), not a silent fix-up.
 */

/**
 * Resolve a provider base URL from the environment, falling back to the
 * vendor default.
 *
 * Trims before the empty-check so a whitespace-only value counts as unset —
 * the same convention as the API keys (see `availableProvidersFromEnv` in
 * index.ts). Without it a stray `OPENAI_BASE_URL="  "` would build the
 * endpoint `"  /chat/completions"` and fail as an unreadable axios error.
 *
 * Throws when the value is not a usable http(s) URL, so a typo fails at the
 * start of the request naming the env var, rather than surfacing several
 * frames deep as a transport error.
 */
export function resolveBaseUrl(envName: string, fallback: string): string {
  const value = process.env[envName]?.trim();
  if (!value) return fallback;

  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(invalidBaseUrl(envName, value));
  }

  // `new URL("localhost:4000")` succeeds — it parses as protocol "localhost:"
  // — so the constructor alone lets a scheme-less host through, and it only
  // fails later inside axios as "Unsupported protocol". Check the scheme here
  // so the "you forgot http://" case gets the same clear message as a typo.
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(invalidBaseUrl(envName, value));
  }

  // Strip trailing slashes so `.../v1` and `.../v1/` produce the same
  // endpoint. Everything else is left exactly as the operator wrote it —
  // normalising further (via URL.href, which appends a slash to a bare origin
  // and re-encodes the path) would mean the URL we call is not the URL they
  // configured.
  return value.replace(/\/+$/, "");
}

function invalidBaseUrl(envName: string, value: string): string {
  return (
    `${envName} is not a valid URL: ${JSON.stringify(value)}. ` +
    `Expected an http(s) base URL such as "http://litellm.litellm.svc.cluster.local:4000/v1" — ` +
    `kguardian appends the provider's request path to it.`
  );
}

/**
 * Extra diagnostics for the failure a wrong base URL actually produces.
 *
 * A misconfigured gateway URL usually still resolves and connects, so there is
 * no connection error to point at — just a 404 (or a 405 when the base exists
 * but does not take POST) whose axios message is "Request failed with status
 * code 404" and whose body is the gateway's HTML. That tells an operator
 * nothing about which URL was called or which env var produced it, and it is
 * the single most likely thing to go wrong when pointing kguardian at
 * LiteLLM. Returns "" for every other status so normal API errors (401, 429,
 * model-not-found) keep their upstream message unadorned.
 */
export function endpointHint(envName: string, endpoint: string, status?: number): string {
  if (status !== 404 && status !== 405) return "";
  return (
    ` (POST ${endpoint} returned ${status} — check ${envName}: it must be the gateway's base URL, ` +
    `to which kguardian appends the request path shown above. If your gateway serves that path ` +
    `under /v1, include /v1 in ${envName}.)`
  );
}
