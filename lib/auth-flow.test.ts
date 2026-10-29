import { describe, expect, it, vi } from "vitest"

import { runLogin, runLoginStep, runRegister, startPasskeyLogin, type AuthFlowDeps } from "./auth-flow"
import { consumeHandoffCode } from "./handoff"
import type { IdpResult } from "./idp/types"
import { createMemoryStore } from "./store"
import { alice, fakeIdp, tokens } from "./test-utils"

const CHAT = "https://chat.localtest.me:4000"
const ok: IdpResult = { ok: true, user: alice, tokens: tokens() }

function setup(idp = fakeIdp({ login: vi.fn(async () => ok), register: vi.fn(async () => ok) })) {
  const store = createMemoryStore()
  const startSession = vi.fn(async () => ({ key: "session:test" }))
  const deps: AuthFlowDeps = {
    store,
    idp,
    allowedParentOrigins: [CHAT],
    handoffTtlSeconds: 60,
    startSession,
  }
  return { deps, store, idp, startSession }
}

function form(fields: Record<string, string>) {
  const data = new FormData()
  for (const [key, value] of Object.entries({ parent: CHAT, ...fields })) data.set(key, value)
  return data
}

const login = (fields: Record<string, string> = {}) =>
  form({ email: " Alice@Example.com ", password: "password123", ...fields })

const register = (fields: Record<string, string> = {}) =>
  form({
    name: "Carol",
    email: "carol@example.com",
    password: "long-enough-1",
    confirmPassword: "long-enough-1",
    ...fields,
  })

describe("runLogin", () => {
  it("logs in, starts a session and mints a code bound to the parent", async () => {
    const { deps, store, idp, startSession } = setup()
    const state = await runLogin(deps, { formData: login(), ip: "1.2.3.4" })

    expect(idp.login).toHaveBeenCalledWith({ email: "alice@example.com", password: "password123" })
    expect(startSession).toHaveBeenCalledWith(alice, ok.ok && ok.tokens)
    expect(state).toMatchObject({ status: "success", user: { name: "Alice Example", email: "alice@example.com" } })
    if (state.status !== "success") return
    expect(await consumeHandoffCode(store, state.code, CHAT)).toMatchObject({ sessionKey: "session:test", user: alice })
  })

  it("refuses an unlisted parent before touching the IdP", async () => {
    const { deps, idp } = setup()
    const state = await runLogin(deps, { formData: login({ parent: "https://evil.example" }), ip: "1.2.3.4" })
    expect(state).toMatchObject({ status: "error", message: expect.stringContaining("chatbot") })
    expect(idp.login).not.toHaveBeenCalled()
  })

  it("returns field errors for invalid input and keeps the email", async () => {
    const { deps, idp } = setup()
    const state = await runLogin(deps, { formData: login({ email: "nope", password: "" }), ip: "1.2.3.4" })
    expect(state).toEqual({
      status: "error",
      fieldErrors: { email: "Enter a valid email address.", password: "Enter your password." },
      values: { email: "nope" },
    })
    expect(idp.login).not.toHaveBeenCalled()
  })

  it("maps IdP errors to messages and never echoes the password", async () => {
    const { deps } = setup(fakeIdp({ login: vi.fn(async () => ({ ok: false as const, error: "invalid_credentials" as const })) }))
    const state = await runLogin(deps, { formData: login(), ip: "1.2.3.4" })
    expect(state).toMatchObject({ status: "error", message: "Email or password is incorrect." })
    expect(JSON.stringify(state)).not.toContain("password123")
  })

  it("rate limits per email across IPs", async () => {
    const { deps, idp } = setup(fakeIdp({ login: vi.fn(async () => ({ ok: false as const, error: "invalid_credentials" as const })) }))
    for (let i = 0; i < 5; i++) await runLogin(deps, { formData: login(), ip: `10.0.0.${i}` })
    const state = await runLogin(deps, { formData: login(), ip: "10.0.0.99" })
    expect(state).toMatchObject({ status: "error", message: expect.stringMatching(/Too many attempts/) })
    expect(idp.login).toHaveBeenCalledTimes(5)
  })

  it("rate limits per IP across emails", async () => {
    const { deps, idp } = setup(fakeIdp({ login: vi.fn(async () => ({ ok: false as const, error: "invalid_credentials" as const })) }))
    for (let i = 0; i < 20; i++) await runLogin(deps, { formData: login({ email: `user${i}@example.com` }), ip: "1.2.3.4" })
    const state = await runLogin(deps, { formData: login({ email: "fresh@example.com" }), ip: "1.2.3.4" })
    expect(state).toMatchObject({ message: expect.stringMatching(/Too many attempts/) })
    expect(idp.login).toHaveBeenCalledTimes(20)
  })

  it("resets the per-email counter after a successful login", async () => {
    const results: IdpResult[] = [
      ...Array.from({ length: 4 }, () => ({ ok: false as const, error: "invalid_credentials" as const })),
      ok,
      ...Array.from({ length: 4 }, () => ({ ok: false as const, error: "invalid_credentials" as const })),
    ]
    const { deps } = setup(fakeIdp({ login: vi.fn(async () => results.shift()!) }))
    for (let i = 0; i < 9; i++) {
      const state = await runLogin(deps, { formData: login(), ip: `10.0.0.${i}` })
      expect(state.status === "error" && state.message?.includes("Too many")).toBeFalsy()
    }
  })
})

describe("runRegister", () => {
  it("registers and hands off", async () => {
    const { deps, idp } = setup()
    const state = await runRegister(deps, { formData: register(), ip: "1.2.3.4" })
    expect(idp.register).toHaveBeenCalledWith({ name: "Carol", email: "carol@example.com", password: "long-enough-1" })
    expect(state.status).toBe("success")
  })

  it("checks the password confirmation and length", async () => {
    const { deps, idp } = setup()
    expect(await runRegister(deps, { formData: register({ confirmPassword: "different" }), ip: "1.2.3.4" })).toMatchObject({
      fieldErrors: { confirmPassword: "Passwords don't match." },
    })
    expect(
      await runRegister(deps, { formData: register({ password: "short", confirmPassword: "short" }), ip: "1.2.3.4" })
    ).toMatchObject({ fieldErrors: { password: "Use at least 8 characters." } })
    expect(idp.register).not.toHaveBeenCalled()
  })

  it("shows the IdP's weak_password on the password field", async () => {
    const { deps } = setup(fakeIdp({ register: vi.fn(async () => ({ ok: false as const, error: "weak_password" as const })) }))
    expect(await runRegister(deps, { formData: register(), ip: "1.2.3.4" })).toEqual({
      status: "error",
      fieldErrors: { password: "Choose a stronger password." },
      values: { email: "carol@example.com", name: "Carol" },
    })
  })

  it("rate limits sign-ups per IP", async () => {
    const { deps } = setup()
    for (let i = 0; i < 5; i++) await runRegister(deps, { formData: register(), ip: "1.2.3.4" })
    expect(await runRegister(deps, { formData: register(), ip: "1.2.3.4" })).toMatchObject({
      message: expect.stringMatching(/Too many attempts/),
    })
  })
})

describe("second factor", () => {
  const OTHER_CHAT = "https://other-chat.localtest.me:4000"
  const passkeyResponse = JSON.stringify({ id: "cred-1", response: {} })

  function mfaSetup(hasPasskey: boolean, overrides: Partial<ReturnType<typeof fakeIdp>> = {}) {
    const idp = fakeIdp({
      login: vi.fn(async () => ({ ok: "mfa_required" as const, transaction: "tx-1", hasPasskey })),
      sendEmailOtp: vi.fn(async () => ({ ok: true as const })),
      verifyEmailOtp: vi.fn(async () => ok),
      passkeyRegistrationOptions: vi.fn(async () => ({ ok: true as const, options: { challenge: "reg" } })),
      verifyPasskeyRegistration: vi.fn(async () => ({ ok: true as const })),
      passkeyAuthenticationOptions: vi.fn(async (transaction?: string) => ({
        ok: true as const,
        transaction: transaction ?? "tx-passkey",
        options: { challenge: "auth" },
      })),
      verifyPasskeyAuthentication: vi.fn(async () => ok),
      ...overrides,
    })
    const context = setup(idp)
    context.deps.allowedParentOrigins = [CHAT, OTHER_CHAT]
    const step = (fields: Record<string, string>) => runLoginStep(context.deps, { formData: form(fields), ip: "1.2.3.4" })
    return { ...context, idp, step }
  }

  async function passwordStep(context: ReturnType<typeof mfaSetup>) {
    const state = await runLogin(context.deps, { formData: login(), ip: "1.2.3.4" })
    if (state.status !== "second_factor") throw new Error(`expected second_factor, got ${state.status}`)
    return state
  }

  it("emails a code when the user has no passkey, without starting a session", async () => {
    const context = mfaSetup(false)
    const state = await passwordStep(context)
    expect(state).toMatchObject({ method: "otp", ticket: expect.any(String) })
    expect(context.idp.sendEmailOtp).toHaveBeenCalledWith("tx-1")
    expect(context.idp.passkeyRegistrationOptions).not.toHaveBeenCalled()
    expect(context.startSession).not.toHaveBeenCalled()
  })

  it("code → offer a passkey → skip completes the login, once", async () => {
    const context = mfaSetup(false)
    const { ticket } = await passwordStep(context)

    expect(await context.step({ intent: "verify_otp", ticket, code: " 123456 " })).toEqual({
      status: "enroll",
      ticket,
      options: { challenge: "reg" },
    })
    expect(context.idp.verifyEmailOtp).toHaveBeenCalledWith("tx-1", "123456")
    expect(context.startSession).not.toHaveBeenCalled()

    const done = await context.step({ intent: "skip_enroll", ticket })
    expect(done).toMatchObject({ status: "success" })
    expect(context.startSession).toHaveBeenCalledWith(alice, ok.ok && ok.tokens)
    if (done.status === "success") {
      expect(await consumeHandoffCode(context.store, done.code, CHAT)).toMatchObject({ user: alice })
    }

    expect(await context.step({ intent: "skip_enroll", ticket })).toMatchObject({
      status: "error",
      message: expect.stringMatching(/expired/),
    })
    expect(context.startSession).toHaveBeenCalledTimes(1)
  })

  it("saves the new passkey, then completes", async () => {
    const context = mfaSetup(false)
    const { ticket } = await passwordStep(context)
    await context.step({ intent: "verify_otp", ticket, code: "123456" })
    expect(await context.step({ intent: "enroll", ticket, response: passkeyResponse })).toMatchObject({ status: "success" })
    expect(context.idp.verifyPasskeyRegistration).toHaveBeenCalledWith("tx-1", { id: "cred-1", response: {} })
  })

  it("refuses to enroll a passkey on the password alone", async () => {
    const context = mfaSetup(false)
    const { ticket } = await passwordStep(context)
    expect(await context.step({ intent: "enroll", ticket, response: passkeyResponse })).toMatchObject({ status: "error" })
    expect(await context.step({ intent: "skip_enroll", ticket })).toMatchObject({ status: "error" })
    expect(context.idp.verifyPasskeyRegistration).not.toHaveBeenCalled()
    expect(context.startSession).not.toHaveBeenCalled()
  })

  it("keeps the code step on a malformed or wrong code", async () => {
    const context = mfaSetup(false, {
      verifyEmailOtp: vi.fn(async () => ({ ok: false as const, error: "invalid_code" as const })),
    })
    const { ticket } = await passwordStep(context)
    expect(await context.step({ intent: "verify_otp", ticket, code: "12" })).toMatchObject({
      status: "second_factor",
      method: "otp",
      fieldErrors: { code: "Enter the 6-digit code from your email." },
    })
    expect(context.idp.verifyEmailOtp).not.toHaveBeenCalled()
    expect(await context.step({ intent: "verify_otp", ticket, code: "654321" })).toMatchObject({
      status: "second_factor",
      fieldErrors: { code: "That code is incorrect or has expired." },
    })
  })

  it("asks for the existing passkey and completes with it", async () => {
    const context = mfaSetup(true)
    const state = await passwordStep(context)
    expect(state).toMatchObject({ method: "passkey", passkeyOptions: { challenge: "auth" } })
    expect(context.idp.passkeyAuthenticationOptions).toHaveBeenCalledWith("tx-1")
    expect(context.idp.sendEmailOtp).not.toHaveBeenCalled()

    expect(await context.step({ intent: "passkey", ticket: state.ticket, response: passkeyResponse })).toMatchObject({
      status: "success",
    })
    expect(context.idp.verifyPasskeyAuthentication).toHaveBeenCalledWith("tx-1", { id: "cred-1", response: {} })
  })

  it("re-prompts with a fresh challenge when the passkey fails, and can fall back to a code", async () => {
    const context = mfaSetup(true, {
      verifyPasskeyAuthentication: vi.fn(async () => ({ ok: false as const, error: "passkey_failed" as const })),
    })
    const { ticket } = await passwordStep(context)
    expect(await context.step({ intent: "passkey", ticket, response: passkeyResponse })).toMatchObject({
      status: "second_factor",
      method: "passkey",
      message: expect.stringMatching(/couldn't be verified/),
    })
    expect(context.idp.passkeyAuthenticationOptions).toHaveBeenCalledTimes(2)

    expect(await context.step({ intent: "send_otp", ticket })).toMatchObject({ status: "second_factor", method: "otp" })
    expect(context.idp.sendEmailOtp).toHaveBeenCalledWith("tx-1")
  })

  it("only accepts the ticket from the parent it was issued for", async () => {
    const context = mfaSetup(false)
    const { ticket } = await passwordStep(context)
    const state = await runLoginStep(context.deps, {
      formData: form({ parent: OTHER_CHAT, intent: "verify_otp", ticket, code: "123456" }),
      ip: "1.2.3.4",
    })
    expect(state).toMatchObject({ status: "error", message: expect.stringMatching(/expired/) })
    expect(context.idp.verifyEmailOtp).not.toHaveBeenCalled()
  })

  it("rejects a made-up ticket and an unknown intent", async () => {
    const context = mfaSetup(false)
    expect(await context.step({ intent: "verify_otp", ticket: "made-up", code: "123456" })).toMatchObject({ status: "error" })
    const { ticket } = await passwordStep(context)
    expect(await context.step({ intent: "nope", ticket })).toMatchObject({ status: "error" })
  })
})

describe("passkey-first login", () => {
  function passkeySetup(verify: IdpResult = ok) {
    const idp = fakeIdp({
      passkeyAuthenticationOptions: vi.fn(async () => ({ ok: true as const, transaction: "tx-pk", options: { challenge: "auth" } })),
      verifyPasskeyAuthentication: vi.fn(async () => verify),
    })
    return setup(idp)
  }

  it("signs in with the passkey alone and skips the second factor", async () => {
    const { deps, idp, startSession } = passkeySetup()
    const challenge = await startPasskeyLogin(deps, { parent: CHAT, ip: "1.2.3.4" })
    expect(challenge).toEqual({ ticket: expect.any(String), options: { challenge: "auth" } })
    expect(idp.passkeyAuthenticationOptions).toHaveBeenCalledWith()

    const formData = form({ intent: "passkey", ticket: challenge!.ticket, response: JSON.stringify({ id: "cred-1" }) })
    expect(await runLoginStep(deps, { formData, ip: "1.2.3.4" })).toMatchObject({ status: "success" })
    expect(idp.verifyPasskeyAuthentication).toHaveBeenCalledWith("tx-pk", { id: "cred-1" })
    expect(idp.sendEmailOtp).not.toHaveBeenCalled()
    expect(startSession).toHaveBeenCalledWith(alice, ok.ok && ok.tokens)

    expect(await runLoginStep(deps, { formData, ip: "1.2.3.4" })).toMatchObject({ status: "error" })
  })

  it("burns the challenge when the passkey fails", async () => {
    const { deps, startSession } = passkeySetup({ ok: false, error: "passkey_failed" })
    const challenge = await startPasskeyLogin(deps, { parent: CHAT, ip: "1.2.3.4" })
    const formData = form({ intent: "passkey", ticket: challenge!.ticket, response: "{}" })
    expect(await runLoginStep(deps, { formData, ip: "1.2.3.4" })).toMatchObject({
      status: "error",
      message: expect.stringMatching(/couldn't be verified/),
    })
    expect(await runLoginStep(deps, { formData, ip: "1.2.3.4" })).toMatchObject({ message: expect.stringMatching(/expired/) })
    expect(startSession).not.toHaveBeenCalled()
  })

  it("rejects malformed responses and unlisted parents", async () => {
    const { deps, idp } = passkeySetup()
    expect(await startPasskeyLogin(deps, { parent: "https://evil.example", ip: "1.2.3.4" })).toBeNull()
    const challenge = await startPasskeyLogin(deps, { parent: CHAT, ip: "1.2.3.4" })
    const formData = form({ intent: "passkey", ticket: challenge!.ticket, response: "not json" })
    expect(await runLoginStep(deps, { formData, ip: "1.2.3.4" })).toMatchObject({ status: "error" })
    expect(idp.verifyPasskeyAuthentication).not.toHaveBeenCalled()
  })
})
