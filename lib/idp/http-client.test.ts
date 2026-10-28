import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest"

import { createMockIdp } from "@/dev/mock-idp/idp"
import { SEED_PASSWORD } from "@/dev/mock-idp/users"

import { createHttpIdpClient, type HttpIdpClientOptions } from "./http-client"

// Runs the adapter against the real mock IdP over HTTP.
let idp: Awaited<ReturnType<typeof createMockIdp>>
let options: HttpIdpClientOptions

beforeAll(async () => {
  idp = await createMockIdp({ maxFailedLogins: 3 })
  const issuer = await idp.start(0)
  options = {
    baseUrl: issuer,
    issuer,
    jwksUrl: `${issuer}/jwks`,
    clientId: "auth-mfe",
    clientSecret: "dev-client-secret",
  }
})
afterAll(() => idp.stop())

// The adapter logs IdP failures; keep test output clean but still assertable.
beforeEach(() => {
  vi.spyOn(console, "error").mockImplementation(() => {})
})

const client = (overrides: Partial<HttpIdpClientOptions> = {}) =>
  createHttpIdpClient({ ...options, ...overrides })

describe("createHttpIdpClient", () => {
  it("logs in and returns verified identity claims", async () => {
    const result = await client().login({ email: "alice@example.com", password: SEED_PASSWORD })
    expect(result).toMatchObject({
      ok: true,
      user: { sub: "mock-user-alice", email: "alice@example.com", name: "Alice Example", emailVerified: true },
    })
    if (!result.ok) return
    expect(result.tokens.refreshToken).toBeTruthy()
    expect(result.tokens.expiresAt).toBeGreaterThan(Date.now())
  })

  it("gives the same error for a wrong password and an unknown email", async () => {
    expect(await client().login({ email: "alice@example.com", password: "wrong" })).toEqual({
      ok: false,
      error: "invalid_credentials",
    })
    expect(await client().login({ email: "nobody@example.com", password: "wrong" })).toEqual({
      ok: false,
      error: "invalid_credentials",
    })
  })

  it("reports a locked account", async () => {
    for (let i = 0; i < 3; i++) await client().login({ email: "bob@example.com", password: "wrong" })
    expect(await client().login({ email: "bob@example.com", password: SEED_PASSWORD })).toEqual({
      ok: false,
      error: "locked",
    })
  })

  it("registers a user, then rejects the same email", async () => {
    const input = { email: "carol@example.com", password: "long-enough-1", name: "Carol" }
    expect(await client().register(input)).toMatchObject({
      ok: true,
      user: { email: "carol@example.com", name: "Carol", emailVerified: false },
    })
    expect(await client().register(input)).toEqual({ ok: false, error: "email_taken" })
    expect(await client().login(input)).toMatchObject({ ok: true })
  })

  it("passes through weak_password", async () => {
    expect(await client().register({ email: "dan@example.com", password: "short", name: "Dan" })).toEqual({
      ok: false,
      error: "weak_password",
    })
  })

  it("refreshes with rotation and rejects the old refresh token", async () => {
    const login = await client().login({ email: "alice@example.com", password: SEED_PASSWORD })
    if (!login.ok) throw new Error("login failed")
    const refreshed = await client().refresh(login.tokens.refreshToken!)
    expect(refreshed).toMatchObject({ ok: true, user: { sub: "mock-user-alice" } })
    if (!refreshed.ok) return
    expect(refreshed.tokens.refreshToken).not.toBe(login.tokens.refreshToken)
    expect(await client().refresh(login.tokens.refreshToken!)).toEqual({ ok: false, error: "invalid_grant" })
  })

  it("logout revokes the refresh token", async () => {
    const login = await client().login({ email: "alice@example.com", password: SEED_PASSWORD })
    if (!login.ok) throw new Error("login failed")
    await client().logout(login.tokens)
    expect(await client().refresh(login.tokens.refreshToken!)).toEqual({ ok: false, error: "invalid_grant" })
  })

  it("treats bad client credentials as unavailable, not as a user error", async () => {
    const result = await client({ clientSecret: "wrong" }).login({
      email: "alice@example.com",
      password: SEED_PASSWORD,
    })
    expect(result).toEqual({ ok: false, error: "unavailable" })
  })

  it("rejects ID tokens with the wrong issuer or audience", async () => {
    const credentials = { email: "alice@example.com", password: SEED_PASSWORD }
    expect(await client({ issuer: "https://someone-else" }).login(credentials)).toEqual({
      ok: false,
      error: "unavailable",
    })

    // Authenticate to the mock as auth-mfe (so it mints aud=auth-mfe) while the
    // adapter expects its own audience to be "other".
    const asAuthMfe: typeof fetch = (input, init) => {
      const headers = new Headers(init?.headers)
      headers.set("authorization", `Basic ${Buffer.from("auth-mfe:dev-client-secret").toString("base64")}`)
      return fetch(input, { ...init, headers })
    }
    expect(await client({ clientId: "other", fetch: asAuthMfe }).login(credentials)).toEqual({
      ok: false,
      error: "unavailable",
    })
    expect(console.error).toHaveBeenCalledWith(expect.stringMatching(/ID token rejected.*"iss"/))
    expect(console.error).toHaveBeenCalledWith(expect.stringMatching(/ID token rejected.*"aud"/))
  })

  it("reports an unreachable IdP as unavailable", async () => {
    const result = await client({ baseUrl: "http://127.0.0.1:9", timeoutMs: 500 }).login({
      email: "alice@example.com",
      password: SEED_PASSWORD,
    })
    expect(result).toEqual({ ok: false, error: "unavailable" })
  })
})
