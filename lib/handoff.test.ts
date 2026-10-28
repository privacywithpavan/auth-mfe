import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { consumeHandoffCode, mintHandoffCode } from "./handoff"
import { createMemoryStore } from "./store"
import { alice } from "./test-utils"

const CHAT = "https://chat.localtest.me:4000"

function mint(store = createMemoryStore()) {
  return mintHandoffCode(store, { sessionKey: "session:abc", user: alice, parentOrigin: CHAT, ttlSeconds: 60 })
}

describe("handoff codes", () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  it("redeems once for the origin it was issued to", async () => {
    const store = createMemoryStore()
    const code = await mint(store)
    const record = await consumeHandoffCode(store, code, CHAT)
    expect(record).toMatchObject({ sessionKey: "session:abc", user: alice, parentOrigin: CHAT })
    expect(await consumeHandoffCode(store, code, CHAT)).toBeUndefined()
  })

  it("is burned by a redemption from the wrong origin", async () => {
    const store = createMemoryStore()
    const code = await mint(store)
    expect(await consumeHandoffCode(store, code, "https://evil.localtest.me")).toBeUndefined()
    expect(await consumeHandoffCode(store, code, CHAT)).toBeUndefined()
  })

  it("expires", async () => {
    const store = createMemoryStore()
    const code = await mint(store)
    vi.advanceTimersByTime(60_000)
    expect(await consumeHandoffCode(store, code, CHAT)).toBeUndefined()
  })

  it("rejects empty and unknown codes", async () => {
    const store = createMemoryStore()
    await mint(store)
    expect(await consumeHandoffCode(store, "", CHAT)).toBeUndefined()
    expect(await consumeHandoffCode(store, "made-up", CHAT)).toBeUndefined()
  })

  it("issues distinct high-entropy codes", async () => {
    const store = createMemoryStore()
    const codes = new Set(await Promise.all(Array.from({ length: 50 }, () => mint(store))))
    expect(codes.size).toBe(50)
    for (const code of codes) expect(code).toMatch(/^[A-Za-z0-9_-]{43}$/)
  })
})
