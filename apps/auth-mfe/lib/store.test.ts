import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { createMemoryStore } from "./store"

describe("createMemoryStore", () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  it("expires values after their TTL", async () => {
    const store = createMemoryStore()
    await store.set("k", { a: 1 }, 10)
    expect(await store.get("k")).toEqual({ a: 1 })
    vi.advanceTimersByTime(10_000)
    expect(await store.get("k")).toBeUndefined()
  })

  it("take returns the value once", async () => {
    const store = createMemoryStore()
    await store.set("k", "v", 10)
    expect(await store.take("k")).toBe("v")
    expect(await store.take("k")).toBeUndefined()
    expect(await store.get("k")).toBeUndefined()
  })

  it("does not share references with callers", async () => {
    const store = createMemoryStore()
    const value = { n: 1 }
    await store.set("k", value, 10)
    value.n = 2
    const read = await store.get<{ n: number }>("k")
    read!.n = 3
    expect(await store.get("k")).toEqual({ n: 1 })
  })

  it("increment keeps one window until it expires", async () => {
    const store = createMemoryStore()
    const first = await store.increment("c", 60)
    vi.advanceTimersByTime(30_000)
    const second = await store.increment("c", 60)
    expect([first.count, second.count]).toEqual([1, 2])
    expect(second.expiresAt).toBe(first.expiresAt)
    vi.advanceTimersByTime(30_000)
    expect((await store.increment("c", 60)).count).toBe(1)
  })
})
