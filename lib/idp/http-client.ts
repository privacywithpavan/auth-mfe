import { createRemoteJWKSet, jwtVerify } from "jose"

import type { IdpClient, IdpError, IdpResult, IdpTokens, IdpUser } from "./types"

/**
 * IdpClient for the in-house IdP's HTTP API. This is the only file that knows its
 * paths and payloads; the shape here matches dev/mock-idp until the real API docs land.
 */
export type HttpIdpClientOptions = {
  baseUrl: string
  issuer: string
  jwksUrl: string
  clientId: string
  clientSecret: string
  timeoutMs?: number
  fetch?: typeof fetch
}

const PATHS = {
  login: "/api/login",
  register: "/api/register",
  logout: "/api/logout",
  token: "/token",
}

const KNOWN_ERRORS = new Set<IdpError>([
  "invalid_credentials",
  "email_taken",
  "weak_password",
  "invalid_request",
  "locked",
  "invalid_grant",
])

type TokenResponse = {
  access_token?: unknown
  refresh_token?: unknown
  id_token?: unknown
  expires_in?: unknown
}

export function createHttpIdpClient({
  baseUrl,
  issuer,
  jwksUrl,
  clientId,
  clientSecret,
  timeoutMs = 5000,
  fetch: fetchImpl = fetch,
}: HttpIdpClientOptions): IdpClient {
  const base = baseUrl.replace(/\/+$/, "")
  const jwks = createRemoteJWKSet(new URL(jwksUrl), { timeoutDuration: timeoutMs })
  const authorization = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`

  async function post(path: string, body: Record<string, string>, form = false) {
    return fetchImpl(`${base}${path}`, {
      method: "POST",
      headers: {
        authorization,
        accept: "application/json",
        "content-type": form ? "application/x-www-form-urlencoded" : "application/json",
      },
      body: form ? new URLSearchParams(body).toString() : JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
      cache: "no-store",
    })
  }

  /** Turns an IdP token response into our types, verifying the ID token. */
  async function toResult(response: Response, action: string): Promise<IdpResult> {
    const body = (await response.json().catch(() => undefined)) as
      | (TokenResponse & { error?: unknown })
      | undefined

    if (!response.ok) {
      const error = body?.error
      if (typeof error === "string" && KNOWN_ERRORS.has(error as IdpError)) {
        return { ok: false, error: error as IdpError }
      }
      // invalid_client and 5xx mean we're misconfigured or the IdP is down, not bad user input.
      console.error(`[idp] ${action} failed: HTTP ${response.status} ${typeof error === "string" ? error : ""}`)
      return { ok: false, error: "unavailable" }
    }

    const { access_token, refresh_token, id_token, expires_in } = body ?? {}
    if (typeof access_token !== "string" || typeof id_token !== "string") {
      console.error(`[idp] ${action}: token response is missing access_token or id_token`)
      return { ok: false, error: "unavailable" }
    }

    let user: IdpUser
    try {
      const { payload } = await jwtVerify(id_token, jwks, { issuer, audience: clientId })
      if (typeof payload.sub !== "string" || typeof payload.email !== "string") {
        throw new Error("ID token is missing sub or email")
      }
      user = {
        sub: payload.sub,
        email: payload.email,
        name: typeof payload.name === "string" ? payload.name : payload.email,
        emailVerified: payload.email_verified === true,
      }
    } catch (error) {
      console.error(`[idp] ${action}: ID token rejected: ${(error as Error).message}`)
      return { ok: false, error: "unavailable" }
    }

    const tokens: IdpTokens = {
      accessToken: access_token,
      refreshToken: typeof refresh_token === "string" ? refresh_token : undefined,
      idToken: id_token,
      expiresAt: Date.now() + (typeof expires_in === "number" ? expires_in : 300) * 1000,
    }
    return { ok: true, user, tokens }
  }

  async function call(action: string, send: () => Promise<Response>): Promise<IdpResult> {
    try {
      return await toResult(await send(), action)
    } catch (error) {
      console.error(`[idp] ${action}: request failed: ${(error as Error).message}`)
      return { ok: false, error: "unavailable" }
    }
  }

  return {
    login: ({ email, password }) => call("login", () => post(PATHS.login, { email, password })),

    register: ({ email, password, name }) =>
      call("register", () => post(PATHS.register, { email, password, name })),

    refresh: (refreshToken) =>
      call("refresh", () =>
        post(PATHS.token, { grant_type: "refresh_token", refresh_token: refreshToken }, true)
      ),

    async logout(tokens) {
      if (!tokens.refreshToken) return
      try {
        await post(PATHS.logout, { refresh_token: tokens.refreshToken })
      } catch (error) {
        console.error(`[idp] logout: request failed: ${(error as Error).message}`)
      }
    },
  }
}
