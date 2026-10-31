import { IDP_ERROR_CODES, IDP_PATHS as PATHS, type TokenResponse as WireTokenResponse } from "@auth-mfe/idp-contract"
import { createRemoteJWKSet, jwtVerify } from "jose"

import type { IdpClient, IdpError, IdpResult, IdpTokens, IdpUser, IdpVoidResult, PasskeyOptions } from "./types"

/**
 * IdpClient for the in-house IdP's HTTP API (paths and payloads in @auth-mfe/idp-contract).
 * This is the only BFF file that knows the wire format.
 */
export type HttpIdpClientOptions = {
  baseUrl: string
  issuer: string
  jwksUrl: string
  clientId: string
  clientSecret: string
  /** Expected `aud` of the session JWT. */
  sessionTokenAudience: string
  timeoutMs?: number
  fetch?: typeof fetch
}

const KNOWN_ERRORS = new Set<string>(IDP_ERROR_CODES)

/** Untrusted until checked. */
type TokenResponse = { [K in keyof WireTokenResponse]?: unknown }

export function createHttpIdpClient({
  baseUrl,
  issuer,
  jwksUrl,
  clientId,
  clientSecret,
  sessionTokenAudience,
  timeoutMs = 5000,
  fetch: fetchImpl = fetch,
}: HttpIdpClientOptions): IdpClient {
  const base = baseUrl.replace(/\/+$/, "")
  const jwks = createRemoteJWKSet(new URL(jwksUrl), { timeoutDuration: timeoutMs })
  const authorization = `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString("base64")}`

  async function post(path: string, body: Record<string, unknown>, form = false) {
    return fetchImpl(`${base}${path}`, {
      method: "POST",
      headers: {
        authorization,
        accept: "application/json",
        "content-type": form ? "application/x-www-form-urlencoded" : "application/json",
      },
      body: form ? new URLSearchParams(body as Record<string, string>).toString() : JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
      cache: "no-store",
    })
  }

  function errorOf(response: Response, body: { error?: unknown } | undefined, action: string): IdpError {
    const error = body?.error
    if (typeof error === "string" && KNOWN_ERRORS.has(error)) return error as IdpError
    // invalid_client and 5xx mean we're misconfigured or the IdP is down, not bad user input.
    console.error(`[idp] ${action} failed: HTTP ${response.status} ${typeof error === "string" ? error : ""}`)
    return "unavailable"
  }

  /** Turns an IdP token response into our types, verifying the ID and session tokens. */
  async function toResult(response: Response, action: string): Promise<IdpResult> {
    const body = (await response.json().catch(() => undefined)) as
      | (TokenResponse & { error?: unknown })
      | undefined

    if (!response.ok) return { ok: false, error: errorOf(response, body, action) }

    const { access_token, refresh_token, id_token, session_token, expires_in } = body ?? {}
    if (typeof access_token !== "string" || typeof id_token !== "string" || typeof session_token !== "string") {
      console.error(`[idp] ${action}: token response is missing access_token, id_token or session_token`)
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

    // The session token goes to the browser and other apps; never set one we wouldn't accept.
    let sessionTokenExpiresAt: number
    try {
      const { payload } = await jwtVerify(session_token, jwks, { issuer, audience: sessionTokenAudience })
      if (payload.sub !== user.sub) throw new Error("session token is for a different subject")
      if (typeof payload.exp !== "number") throw new Error("session token has no exp")
      sessionTokenExpiresAt = payload.exp * 1000
    } catch (error) {
      console.error(`[idp] ${action}: session token rejected: ${(error as Error).message}`)
      return { ok: false, error: "unavailable" }
    }

    const tokens: IdpTokens = {
      accessToken: access_token,
      refreshToken: typeof refresh_token === "string" ? refresh_token : undefined,
      idToken: id_token,
      expiresAt: Date.now() + (typeof expires_in === "number" ? expires_in : 300) * 1000,
      sessionToken: session_token,
      sessionTokenExpiresAt,
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

  /** For calls that don't return tokens: the JSON body (empty for 204), or a mapped error. */
  async function callJson(
    action: string,
    send: () => Promise<Response>
  ): Promise<{ ok: true; body: Record<string, unknown> } | { ok: false; error: IdpError }> {
    try {
      const response = await send()
      const body = (await response.json().catch(() => undefined)) as Record<string, unknown> | undefined
      if (!response.ok) return { ok: false, error: errorOf(response, body, action) }
      return { ok: true, body: body ?? {} }
    } catch (error) {
      console.error(`[idp] ${action}: request failed: ${(error as Error).message}`)
      return { ok: false, error: "unavailable" }
    }
  }

  function malformed(action: string): { ok: false; error: IdpError } {
    console.error(`[idp] ${action}: unexpected response body`)
    return { ok: false, error: "unavailable" }
  }

  const isObject = (value: unknown): value is PasskeyOptions =>
    typeof value === "object" && value !== null && !Array.isArray(value)

  const done = (result: { ok: true } | { ok: false; error: IdpError }): IdpVoidResult =>
    result.ok ? { ok: true } : result

  return {
    async login({ email, password }) {
      try {
        const response = await post(PATHS.login, { email, password })
        // A second factor is pending: 200 without tokens.
        const peek = response.ok ? await response.clone().json().catch(() => undefined) : undefined
        if (peek?.mfa_required === true) {
          if (typeof peek.mfa_token !== "string") return malformed("login")
          return { ok: "mfa_required", transaction: peek.mfa_token, hasPasskey: peek.has_passkey === true }
        }
        return await toResult(response, "login")
      } catch (error) {
        console.error(`[idp] login: request failed: ${(error as Error).message}`)
        return { ok: false, error: "unavailable" }
      }
    },

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

    sendEmailOtp: async (transaction) =>
      done(await callJson("otp send", () => post(PATHS.otpSend, { mfa_token: transaction }))),

    verifyEmailOtp: (transaction, code) =>
      call("otp verify", () => post(PATHS.otpVerify, { mfa_token: transaction, code })),

    async passkeyRegistrationOptions(transaction) {
      const result = await callJson("passkey registration options", () =>
        post(PATHS.passkeyRegistrationOptions, { mfa_token: transaction })
      )
      if (!result.ok) return result
      const { options } = result.body
      return isObject(options) ? { ok: true, options } : malformed("passkey registration options")
    },

    verifyPasskeyRegistration: async (transaction, response) =>
      done(
        await callJson("passkey registration", () =>
          post(PATHS.passkeyRegistrationVerify, { mfa_token: transaction, response })
        )
      ),

    async passkeyAuthenticationOptions(transaction) {
      const result = await callJson("passkey authentication options", () =>
        post(PATHS.passkeyAuthenticationOptions, transaction ? { mfa_token: transaction } : {})
      )
      if (!result.ok) return result
      const { transaction: id, options } = result.body
      return typeof id === "string" && isObject(options)
        ? { ok: true, transaction: id, options }
        : malformed("passkey authentication options")
    },

    verifyPasskeyAuthentication: (transaction, response) =>
      call("passkey authentication", () => post(PATHS.passkeyAuthenticationVerify, { transaction, response })),
  }
}
