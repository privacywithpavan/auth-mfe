import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { hitRateLimit, resetRateLimit, type RateLimitRule } from "./rate-limit"
import { createMemoryStore } from "./store"

const rule: RateLimitRule = { name: "test", limit: 3, windowSeconds: 60 }

describe("rate limiting", () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  it("allows up to the limit, then blocks until the window ends", async () => {
    const store = createMemoryStore()
    for (let i = 0; i < 3; i++) expect(await hitRateLimit(store, rule, "a")).toEqual({ allowed: true })
    vi.advanceTimersByTime(20_000)
    expect(await hitRateLimit(store, rule, "a")).toEqual({ allowed: false, retryAfterSeconds: 40 })
    vi.advanceTimersByTime(40_000)
    expect(await hitRateLimit(store, rule, "a")).toEqual({ allowed: true })
  })

  it("counts subjects separately and case-insensitively", async () => {
    const store = createMemoryStore()
    for (let i = 0; i < 3; i++) await hitRateLimit(store, rule, "Alice@Example.com")
    expect((await hitRateLimit(store, rule, "alice@example.com")).allowed).toBe(false)
    expect((await hitRateLimit(store, rule, "bob@example.com")).allowed).toBe(true)
  })

  it("reset clears the counter", async () => {
    const store = createMemoryStore()
    for (let i = 0; i < 4; i++) await hitRateLimit(store, rule, "a")
    await resetRateLimit(store, rule, "a")
    expect((await hitRateLimit(store, rule, "a")).allowed).toBe(true)
  })
})
