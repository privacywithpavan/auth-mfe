import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { createSession, destroySession, getActiveSession, readSession, sessionKey } from "./session"
import { createMemoryStore } from "./store"
import { alice, fakeIdp, tokens } from "./test-utils"

describe("sessions", () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  it("stores the session under a hash of the id, not the id itself", async () => {
    const store = createMemoryStore()
    const { sessionId, key } = await createSession(store, { user: alice, tokens: tokens(), ttlSeconds: 60 })
    expect(sessionId).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(key).toBe(sessionKey(sessionId))
    expect(key).not.toContain(sessionId)
    expect((await readSession(store, key))?.user).toEqual(alice)
  })

  it("expires with its TTL", async () => {
    const store = createMemoryStore()
    const { key } = await createSession(store, { user: alice, tokens: tokens(), ttlSeconds: 60 })
    vi.advanceTimersByTime(60_000)
    expect(await readSession(store, key)).toBeUndefined()
  })

  it("returns a session with a fresh access token without calling the IdP", async () => {
    const store = createMemoryStore()
    const idp = fakeIdp()
    const { key } = await createSession(store, { user: alice, tokens: tokens(), ttlSeconds: 3600 })
    expect(await getActiveSession(store, idp, key)).toBeDefined()
    expect(idp.refresh).not.toHaveBeenCalled()
  })

  it("refreshes an access token that is about to expire", async () => {
    const store = createMemoryStore()
    const renewed = tokens({ accessToken: "access-2", refreshToken: "refresh-2" })
    const idp = fakeIdp({ refresh: vi.fn(async () => ({ ok: true as const, user: alice, tokens: renewed })) })
    const { key } = await createSession(store, {
      user: alice,
      tokens: tokens({ expiresAt: Date.now() + 30_000 }),
      ttlSeconds: 3600,
    })

    const session = await getActiveSession(store, idp, key)

    expect(idp.refresh).toHaveBeenCalledWith("refresh")
    expect(session?.tokens.accessToken).toBe("access-2")
    expect((await readSession(store, key))?.tokens.refreshToken).toBe("refresh-2")
  })

  it("ends the session when the IdP rejects the refresh token", async () => {
    const store = createMemoryStore()
    const idp = fakeIdp({ refresh: vi.fn(async () => ({ ok: false as const, error: "invalid_grant" as const })) })
    const { key } = await createSession(store, {
      user: alice,
      tokens: tokens({ expiresAt: Date.now() + 30_000 }),
      ttlSeconds: 3600,
    })
    expect(await getActiveSession(store, idp, key)).toBeUndefined()
    expect(await readSession(store, key)).toBeUndefined()
  })

  it("rides out an IdP outage while the access token is still valid", async () => {
    const store = createMemoryStore()
    const idp = fakeIdp({ refresh: vi.fn(async () => ({ ok: false as const, error: "unavailable" as const })) })
    const { key } = await createSession(store, {
      user: alice,
      tokens: tokens({ expiresAt: Date.now() + 30_000 }),
      ttlSeconds: 3600,
    })
    expect(await getActiveSession(store, idp, key)).toBeDefined()
    vi.advanceTimersByTime(30_000)
    expect(await getActiveSession(store, idp, key)).toBeUndefined()
  })

  it("destroy removes the session and revokes at the IdP", async () => {
    const store = createMemoryStore()
    const idp = fakeIdp()
    const { key } = await createSession(store, { user: alice, tokens: tokens(), ttlSeconds: 60 })
    await destroySession(store, idp, key)
    expect(await readSession(store, key)).toBeUndefined()
    expect(idp.logout).toHaveBeenCalledWith(expect.objectContaining({ refreshToken: "refresh" }))
  })
})
