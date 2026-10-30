/**
 * Small TTL key-value store shared by sessions, MFA tickets and rate limits.
 * The memory implementation is single-process only; a Redis implementation of the
 * same interface (GETDEL for `take`, INCR + EXPIRE for `increment`) replaces it
 * before running more than one instance.
 */
export interface KeyValueStore {
  get<T>(key: string): Promise<T | undefined>
  set<T>(key: string, value: T, ttlSeconds: number): Promise<void>
  delete(key: string): Promise<void>
  /** Atomically read and delete. Used for single-use values. */
  take<T>(key: string): Promise<T | undefined>
  /** Increment a counter, starting a TTL window on first use. */
  increment(key: string, ttlSeconds: number): Promise<{ count: number; expiresAt: number }>
}

type Entry = { value: unknown; expiresAt: number }

export function createMemoryStore(now: () => number = Date.now): KeyValueStore {
  const entries = new Map<string, Entry>()

  function live(key: string): Entry | undefined {
    const entry = entries.get(key)
    if (entry && entry.expiresAt <= now()) {
      entries.delete(key)
      return undefined
    }
    return entry
  }

  // Drop expired entries now and then so the map doesn't grow without bound.
  const sweep = setInterval(() => {
    for (const key of entries.keys()) live(key)
  }, 60_000)
  sweep.unref?.()

  return {
    // Values are cloned in and out, like a networked store would serialize them,
    // so callers can't depend on shared references.
    async get<T>(key: string) {
      const entry = live(key)
      return entry && (structuredClone(entry.value) as T)
    },
    async set(key, value, ttlSeconds) {
      entries.set(key, { value: structuredClone(value), expiresAt: now() + ttlSeconds * 1000 })
    },
    async delete(key) {
      entries.delete(key)
    },
    async take<T>(key: string) {
      const entry = live(key)
      entries.delete(key)
      return entry?.value as T | undefined
    },
    async increment(key, ttlSeconds) {
      const entry = live(key) ?? { value: 0, expiresAt: now() + ttlSeconds * 1000 }
      entry.value = (entry.value as number) + 1
      entries.set(key, entry)
      return { count: entry.value as number, expiresAt: entry.expiresAt }
    },
  }
}

const globalForStore = globalThis as typeof globalThis & { __authMfeStore?: KeyValueStore }

/** Process-wide store. Kept on globalThis so dev hot reloads don't wipe sessions. */
export function getStore(): KeyValueStore {
  globalForStore.__authMfeStore ??= createMemoryStore()
  return globalForStore.__authMfeStore
}
