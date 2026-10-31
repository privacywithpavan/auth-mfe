/**
 * Server-side check of the `auth_token` cookie for apps on the org root domain (the
 * chatbot backend and anything else that trusts the auth MFE's sign-in). After login the
 * auth BFF sets it to the IdP's short-lived session JWT; verify it on every request.
 *
 *   const verifier = createAuthTokenVerifier({ issuer, jwksUrl, audience: "chatbot" })
 *   const user = await verifier.fromCookieHeader(req.headers.cookie)
 *   if (!user) // 401: the page calls refreshAuthSession() from @auth-mfe/sdk and retries
 *
 * The cookie is sent by every subdomain, so SameSite doesn't stop CSRF from a sibling:
 * state-changing routes must also check Origin.
 */
import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from "jose"

export const AUTH_TOKEN_COOKIE = "auth_token"

export type AuthTokenUser = { sub: string; email: string; name: string }

export type AuthTokenVerifierOptions = {
  /** The IdP issuer, the session JWT's `iss`. */
  issuer: string
  /** The session token audience the IdP issues for your app, e.g. "chatbot". */
  audience: string
  /** Clock skew allowed on `exp`, `nbf` and `iat`. */
  clockToleranceSeconds?: number
  /** Called with the reason a token was rejected, e.g. for logging. */
  onReject?: (error: Error) => void
} & (
  | { /** The IdP's JWKS, e.g. https://idp.example.com/jwks. */ jwksUrl: string; jwks?: never }
  | { jwksUrl?: never; /** A key source, e.g. createLocalJWKSet() in tests. */ jwks: JWTVerifyGetKey }
)

/**
 * Cookie tossing: a sibling subdomain can plant its own `auth_token` next to ours, so
 * every value is tried. Capped so a flood of planted cookies can't cost many verifications.
 */
const MAX_COOKIE_VALUES = 3

/** Every `auth_token` value in a Cookie header, in header order. */
export function readAuthTokenCookies(cookieHeader: string | null | undefined): string[] {
  if (!cookieHeader) return []
  const values: string[] = []
  for (const pair of cookieHeader.split(";")) {
    const separator = pair.indexOf("=")
    if (separator === -1 || pair.slice(0, separator).trim() !== AUTH_TOKEN_COOKIE) continue
    const value = pair.slice(separator + 1).trim()
    if (value) values.push(value)
  }
  return values
}

export function createAuthTokenVerifier(options: AuthTokenVerifierOptions) {
  const { issuer, audience, clockToleranceSeconds = 30, onReject } = options
  const keys = options.jwks ?? createRemoteJWKSet(new URL(options.jwksUrl))

  /** The signed-in user, or undefined when the token is expired, malformed or not from our IdP. */
  async function verify(token: string): Promise<AuthTokenUser | undefined> {
    try {
      const { payload } = await jwtVerify(token, keys, {
        issuer,
        audience,
        algorithms: ["RS256"],
        clockTolerance: clockToleranceSeconds,
        requiredClaims: ["exp"],
      })
      if (typeof payload.sub !== "string" || typeof payload.email !== "string") {
        throw new Error("auth_token is missing sub or email")
      }
      return {
        sub: payload.sub,
        email: payload.email,
        name: typeof payload.name === "string" ? payload.name : payload.email,
      }
    } catch (error) {
      onReject?.(error as Error)
      return undefined
    }
  }

  /** The user from the first valid `auth_token` in a Cookie header. */
  async function fromCookieHeader(cookieHeader: string | null | undefined): Promise<AuthTokenUser | undefined> {
    for (const token of readAuthTokenCookies(cookieHeader).slice(0, MAX_COOKIE_VALUES)) {
      const user = await verify(token)
      if (user) return user
    }
    return undefined
  }

  return { verify, fromCookieHeader }
}
