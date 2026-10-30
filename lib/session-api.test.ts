import { describe, expect, it, vi } from "vitest"

import { handleLogout, handlePreflight, handleRefresh, type SessionApiDeps } from "./session-api"
import type { Session } from "./session"
import { alice, tokens } from "./test-utils"

const CHAT = "https://chat.localtest.me:4000"

function setup(session?: Session) {
  const deps = {
    allowedParentOrigins: [CHAT],
    getCurrentSession: vi.fn(async () => (session ? { session } : undefined)),
    setAuthTokenCookie: vi.fn(async () => {}),
    clearAuthTokenCookie: vi.fn(async () => {}),
    endSession: vi.fn(async () => {}),
  } satisfies SessionApiDeps
  return deps
}

const session = (): Session => ({
  user: alice,
  tokens: tokens({ sessionTokenExpiresAt: Date.parse("2030-01-01T00:10:00Z") }),
  createdAt: Date.now(),
  expiresAt: Date.now() + 3600_000,
})

const post = (path: string, origin: string | null = CHAT) =>
  new Request(`https://auth.localtest.me:3000${path}`, {
    method: "POST",
    headers: origin ? { origin } : {},
  })

describe("session API", () => {
  it("refresh re-sets auth_token and returns the user, with CORS for the parent", async () => {
    const current = session()
    const deps = setup(current)
    const response = await handleRefresh(post("/api/session/refresh"), deps)

    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({
      user: { sub: alice.sub, email: alice.email, name: alice.name },
      expires_at: "2030-01-01T00:10:00.000Z",
    })
    expect(deps.setAuthTokenCookie).toHaveBeenCalledWith(current.tokens)
    expect(response.headers.get("access-control-allow-origin")).toBe(CHAT)
    expect(response.headers.get("access-control-allow-credentials")).toBe("true")
    expect(response.headers.get("vary")).toBe("Origin")
    expect(response.headers.get("cache-control")).toBe("no-store")
  })

  it("refresh without a session clears auth_token and returns 401", async () => {
    const deps = setup()
    const response = await handleRefresh(post("/api/session/refresh"), deps)
    expect(response.status).toBe(401)
    expect(await response.json()).toEqual({ error: "unauthenticated" })
    expect(deps.clearAuthTokenCookie).toHaveBeenCalled()
    expect(response.headers.get("access-control-allow-origin")).toBe(CHAT)
  })

  it.each([
    ["no Origin", null],
    ["a sibling subdomain", "https://evil.localtest.me"],
    ["a look-alike origin", "https://chat.localtest.me:4000.evil.example"],
  ])("rejects %s without touching the session", async (_label, origin) => {
    const deps = setup(session())
    for (const response of [
      await handleRefresh(post("/api/session/refresh", origin), deps),
      await handleLogout(post("/api/session/logout", origin), deps),
      handlePreflight(post("/api/session/refresh", origin), deps),
    ]) {
      expect(response.status).toBe(403)
      expect(response.headers.get("access-control-allow-origin")).toBeNull()
    }
    expect(deps.getCurrentSession).not.toHaveBeenCalled()
    expect(deps.setAuthTokenCookie).not.toHaveBeenCalled()
    expect(deps.endSession).not.toHaveBeenCalled()
  })

  it("logout ends the session and is idempotent", async () => {
    const deps = setup()
    for (let i = 0; i < 2; i++) {
      const response = await handleLogout(post("/api/session/logout"), deps)
      expect(response.status).toBe(204)
      expect(response.headers.get("access-control-allow-origin")).toBe(CHAT)
    }
    expect(deps.endSession).toHaveBeenCalledTimes(2)
  })

  it("answers preflight for the parent", () => {
    const response = handlePreflight(post("/api/session/refresh"), setup())
    expect(response.status).toBe(204)
    expect(response.headers.get("access-control-allow-methods")).toBe("POST")
    expect(response.headers.get("access-control-allow-origin")).toBe(CHAT)
  })
})
