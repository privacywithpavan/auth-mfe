import { beforeEach, describe, expect, it, vi } from "vitest"

import { mintHandoffCode } from "./handoff"
import { handleExchange, handleLogout, type HandoffApiDeps } from "./handoff-api"
import { createSession, readSession } from "./session"
import { createMemoryStore } from "./store"
import { alice, fakeIdp, tokens } from "./test-utils"

const CHAT = "https://chat.localtest.me:4000"
const CLIENT = { clientId: "chatbot", clientSecret: "s".repeat(32) }

function basic(id = CLIENT.clientId, secret = CLIENT.clientSecret) {
  return `Basic ${Buffer.from(`${id}:${secret}`).toString("base64")}`
}

function post(path: string, body: unknown, { authorization = basic(), contentType = "application/json" } = {}) {
  return new Request(`https://auth.localtest.me${path}`, {
    method: "POST",
    headers: { authorization, "content-type": contentType },
    body: typeof body === "string" ? body : JSON.stringify(body),
  })
}

async function setup() {
  const store = createMemoryStore()
  const idp = fakeIdp()
  const deps: HandoffApiDeps = { store, idp, ...CLIENT }
  const { key } = await createSession(store, { user: alice, tokens: tokens(), ttlSeconds: 3600 })
  const code = await mintHandoffCode(store, { sessionKey: key, user: alice, parentOrigin: CHAT, ttlSeconds: 60 })
  return { deps, store, idp, key, code }
}

beforeEach(() => {
  vi.spyOn(console, "info").mockImplementation(() => {})
})

describe("POST /api/handoff/exchange", () => {
  it("returns identity claims and a session ref, once", async () => {
    const { deps, code, key } = await setup()
    const response = await handleExchange(post("/api/handoff/exchange", { code, parent_origin: CHAT }), deps)

    expect(response.status).toBe(200)
    expect(response.headers.get("cache-control")).toBe("no-store")
    const body = await response.json()
    expect(body).toEqual({
      user: { sub: alice.sub, email: alice.email, name: alice.name, email_verified: true },
      session_ref: key,
      session_expires_at: expect.any(String),
    })
    expect(JSON.stringify(body)).not.toMatch(/access|refresh|id_token/)

    const replay = await handleExchange(post("/api/handoff/exchange", { code, parent_origin: CHAT }), deps)
    expect(replay.status).toBe(400)
    expect(await replay.json()).toEqual({ error: "invalid_grant" })
  })

  it.each([
    ["no credentials", ""],
    ["wrong secret", basic("chatbot", "wrong")],
    ["wrong id", basic("other", CLIENT.clientSecret)],
    ["bearer scheme", "Bearer abc"],
  ])("rejects %s with 401 and keeps the code usable", async (_label, authorization) => {
    const { deps, code } = await setup()
    const response = await handleExchange(post("/api/handoff/exchange", { code, parent_origin: CHAT }, { authorization }), deps)
    expect(response.status).toBe(401)
    expect(response.headers.get("www-authenticate")).toContain("Basic")
    const ok = await handleExchange(post("/api/handoff/exchange", { code, parent_origin: CHAT }), deps)
    expect(ok.status).toBe(200)
  })

  it("rejects a code issued to another origin", async () => {
    const { deps, code } = await setup()
    const response = await handleExchange(
      post("/api/handoff/exchange", { code, parent_origin: "https://other.localtest.me" }),
      deps
    )
    expect(response.status).toBe(400)
  })

  it("rejects a code whose session has already ended", async () => {
    const { deps, code, key, store } = await setup()
    await store.delete(key)
    const response = await handleExchange(post("/api/handoff/exchange", { code, parent_origin: CHAT }), deps)
    expect(await response.json()).toEqual({ error: "invalid_grant" })
  })

  it("requires a JSON body with code and parent_origin", async () => {
    const { deps, code } = await setup()
    expect((await handleExchange(post("/api/handoff/exchange", { code }), deps)).status).toBe(400)
    expect((await handleExchange(post("/api/handoff/exchange", "{not json"), deps)).status).toBe(400)
    expect(
      (await handleExchange(post("/api/handoff/exchange", `code=${code}`, { contentType: "application/x-www-form-urlencoded" }), deps))
        .status
    ).toBe(415)
  })
})

describe("POST /api/handoff/logout", () => {
  it("ends the session and revokes at the IdP", async () => {
    const { deps, key, store, idp } = await setup()
    const response = await handleLogout(post("/api/handoff/logout", { session_ref: key }), deps)
    expect(response.status).toBe(204)
    expect(await readSession(store, key)).toBeUndefined()
    expect(idp.logout).toHaveBeenCalledOnce()
  })

  it("is idempotent and ignores refs that aren't session keys", async () => {
    const { deps, key, idp } = await setup()
    await handleLogout(post("/api/handoff/logout", { session_ref: key }), deps)
    expect((await handleLogout(post("/api/handoff/logout", { session_ref: key }), deps)).status).toBe(204)
    expect((await handleLogout(post("/api/handoff/logout", { session_ref: "handoff:x" }), deps)).status).toBe(204)
    expect(idp.logout).toHaveBeenCalledOnce()
  })

  it("requires client credentials", async () => {
    const { deps, key, store } = await setup()
    const response = await handleLogout(post("/api/handoff/logout", { session_ref: key }, { authorization: "" }), deps)
    expect(response.status).toBe(401)
    expect(await readSession(store, key)).toBeDefined()
  })
})
