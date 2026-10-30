import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest"

import { createMockIdp } from "@/dev/mock-idp/idp"
import { SEED_PASSWORD } from "@/dev/mock-idp/users"

import { createHttpIdpClient, type HttpIdpClientOptions } from "./http-client"

// Runs the adapter against the real mock IdP over HTTP.
let idp: Awaited<ReturnType<typeof createMockIdp>>
let options: HttpIdpClientOptions

beforeAll(async () => {
  idp = await createMockIdp({ maxFailedLogins: 3, requireMfa: false })
  const issuer = await idp.start(0)
  options = {
    baseUrl: issuer,
    issuer,
    jwksUrl: `${issuer}/jwks`,
    clientId: "auth-mfe",
    clientSecret: "dev-client-secret",
    sessionTokenAudience: "chatbot",
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
    if (result.ok !== true) return
    expect(result.tokens.refreshToken).toBeTruthy()
    expect(result.tokens.expiresAt).toBeGreaterThan(Date.now())
    expect(result.tokens.sessionToken.split(".")).toHaveLength(3)
    expect(result.tokens.sessionTokenExpiresAt).toBeGreaterThan(Date.now())
    expect(result.tokens.sessionTokenExpiresAt).toBeLessThanOrEqual(Date.now() + 600_000)
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
    if (login.ok !== true) throw new Error("login failed")
    const refreshed = await client().refresh(login.tokens.refreshToken!)
    expect(refreshed).toMatchObject({ ok: true, user: { sub: "mock-user-alice" } })
    if (!refreshed.ok) return
    expect(refreshed.tokens.refreshToken).not.toBe(login.tokens.refreshToken)
    expect(refreshed.tokens.sessionToken).not.toBe(login.tokens.sessionToken)
    expect(await client().refresh(login.tokens.refreshToken!)).toEqual({ ok: false, error: "invalid_grant" })
  })

  it("logout revokes the refresh token", async () => {
    const login = await client().login({ email: "alice@example.com", password: SEED_PASSWORD })
    if (login.ok !== true) throw new Error("login failed")
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

  it("rejects a session token with the wrong audience", async () => {
    const result = await client({ sessionTokenAudience: "other" }).login({
      email: "alice@example.com",
      password: SEED_PASSWORD,
    })
    expect(result).toEqual({ ok: false, error: "unavailable" })
    expect(console.error).toHaveBeenCalledWith(expect.stringMatching(/session token rejected.*"aud"/))
  })

  it("rejects a token response without a session token", async () => {
    const withoutSessionToken: typeof fetch = async (input, init) => {
      const body = await (await fetch(input, init)).json()
      delete body.session_token
      return Response.json(body)
    }
    const result = await client({ fetch: withoutSessionToken }).login({
      email: "alice@example.com",
      password: SEED_PASSWORD,
    })
    expect(result).toEqual({ ok: false, error: "unavailable" })
  })

  it("rejects a session token issued for another user", async () => {
    const erin = { email: "erin@example.com", password: "long-enough-1", name: "Erin" }
    const other = await client().register(erin)
    if (other.ok !== true) throw new Error("register failed")
    const swapped: typeof fetch = async (input, init) => {
      const body = await (await fetch(input, init)).json()
      return Response.json({ ...body, session_token: other.tokens.sessionToken })
    }
    expect(await client({ fetch: swapped }).login({ email: "alice@example.com", password: SEED_PASSWORD })).toEqual({
      ok: false,
      error: "unavailable",
    })
    expect(console.error).toHaveBeenCalledWith(expect.stringMatching(/session token rejected.*different subject/))
  })

  it("reports an unreachable IdP as unavailable", async () => {
    const result = await client({ baseUrl: "http://127.0.0.1:9", timeoutMs: 500 }).login({
      email: "alice@example.com",
      password: SEED_PASSWORD,
    })
    expect(result).toEqual({ ok: false, error: "unavailable" })
  })
})

describe("createHttpIdpClient with a second factor", () => {
  let mfaIdp: Awaited<ReturnType<typeof createMockIdp>>
  let mfaOptions: HttpIdpClientOptions
  const codes = new Map<string, string>()
  const alice = { email: "alice@example.com", password: SEED_PASSWORD }

  beforeAll(async () => {
    mfaIdp = await createMockIdp({ onOtp: (email, code) => codes.set(email, code) })
    const issuer = await mfaIdp.start(0)
    mfaOptions = { ...options, baseUrl: issuer, issuer, jwksUrl: `${issuer}/jwks` }
  })
  afterAll(() => mfaIdp.stop())
  beforeEach(() => {
    vi.spyOn(console, "warn").mockImplementation(() => {})
  })

  const mfaClient = () => createHttpIdpClient(mfaOptions)

  async function passwordLogin() {
    const login = await mfaClient().login(alice)
    if (login.ok !== "mfa_required") throw new Error("expected mfa_required")
    return login.transaction
  }

  const wrongCode = (code: string) => (code === "000000" ? "111111" : "000000")

  it("asks for a second factor, then issues tokens for the emailed code", async () => {
    expect(await mfaClient().login(alice)).toEqual({ ok: "mfa_required", transaction: expect.any(String), hasPasskey: false })
    const transaction = await passwordLogin()
    expect(await mfaClient().sendEmailOtp(transaction)).toEqual({ ok: true })
    const code = codes.get(alice.email)!
    expect(await mfaClient().verifyEmailOtp(transaction, wrongCode(code))).toEqual({ ok: false, error: "invalid_code" })
    expect(await mfaClient().verifyEmailOtp(transaction, code)).toMatchObject({ ok: true, user: { sub: "mock-user-alice" } })
  })

  it("only offers passkey creation once the second factor passed", async () => {
    const transaction = await passwordLogin()
    expect(await mfaClient().passkeyRegistrationOptions(transaction)).toEqual({ ok: false, error: "invalid_grant" })
    await mfaClient().sendEmailOtp(transaction)
    await mfaClient().verifyEmailOtp(transaction, codes.get(alice.email)!)
    expect(await mfaClient().passkeyRegistrationOptions(transaction)).toMatchObject({
      ok: true,
      options: {
        rp: { id: "auth.localtest.me" },
        challenge: expect.any(String),
        authenticatorSelection: { residentKey: "required", userVerification: "required" },
      },
    })
    expect(await mfaClient().verifyPasskeyRegistration(transaction, { id: "bogus", response: {} })).toEqual({
      ok: false,
      error: "passkey_failed",
    })
  })

  it("ends the transaction after too many wrong codes", async () => {
    const transaction = await passwordLogin()
    await mfaClient().sendEmailOtp(transaction)
    const wrong = wrongCode(codes.get(alice.email)!)
    for (let i = 0; i < 4; i++) await mfaClient().verifyEmailOtp(transaction, wrong)
    expect(await mfaClient().verifyEmailOtp(transaction, wrong)).toEqual({ ok: false, error: "invalid_grant" })
    expect(await mfaClient().verifyEmailOtp(transaction, codes.get(alice.email)!)).toEqual({ ok: false, error: "invalid_grant" })
  })

  it("starts a passkey-first login and burns its challenge on a bad response", async () => {
    const start = await mfaClient().passkeyAuthenticationOptions()
    expect(start).toMatchObject({ ok: true, transaction: expect.any(String), options: { challenge: expect.any(String), userVerification: "required" } })
    if (!start.ok) return
    expect(await mfaClient().verifyPasskeyAuthentication(start.transaction, { id: "unknown", response: {} })).toEqual({
      ok: false,
      error: "passkey_failed",
    })
    expect(await mfaClient().verifyPasskeyAuthentication(start.transaction, { id: "unknown", response: {} })).toEqual({
      ok: false,
      error: "invalid_grant",
    })
  })

  it("won't ask for a passkey the user doesn't have", async () => {
    expect(await mfaClient().passkeyAuthenticationOptions(await passwordLogin())).toEqual({ ok: false, error: "invalid_request" })
  })
})
