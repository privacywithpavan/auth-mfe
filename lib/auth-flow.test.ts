import { describe, expect, it, vi } from "vitest"

import { runLogin, runRegister, type AuthFlowDeps } from "./auth-flow"
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
