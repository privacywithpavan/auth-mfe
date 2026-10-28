import { randomBytes, randomUUID, scryptSync, timingSafeEqual } from "node:crypto"

export type MockUser = {
  sub: string
  email: string
  email_verified: boolean
  name: string
}

type StoredUser = MockUser & { passwordHash: string }

export const SEED_PASSWORD = "password123"

function hashPassword(password: string) {
  const salt = randomBytes(16)
  return `${salt.toString("hex")}:${scryptSync(password, salt, 32).toString("hex")}`
}

function verifyPassword(password: string, stored: string) {
  const [salt, hash] = stored.split(":")
  const expected = Buffer.from(hash, "hex")
  const actual = scryptSync(password, Buffer.from(salt, "hex"), expected.length)
  return timingSafeEqual(actual, expected)
}

function publicUser(stored: StoredUser): MockUser {
  const { sub, email, email_verified, name } = stored
  return { sub, email, email_verified, name }
}

/** In-memory user directory, seeded with alice and bob. */
export function createUserDirectory() {
  const byEmail = new Map<string, StoredUser>()

  function add(user: MockUser, password: string) {
    byEmail.set(user.email.toLowerCase(), { ...user, passwordHash: hashPassword(password) })
  }

  add({ sub: "mock-user-alice", email: "alice@example.com", email_verified: true, name: "Alice Example" }, SEED_PASSWORD)
  add({ sub: "mock-user-bob", email: "bob@example.com", email_verified: true, name: "Bob Example" }, SEED_PASSWORD)

  return {
    findBySub(sub: string): MockUser | undefined {
      for (const user of byEmail.values()) if (user.sub === sub) return publicUser(user)
    },

    authenticate(email: string, password: string): MockUser | undefined {
      const user = byEmail.get(email.toLowerCase())
      // Hash anyway on unknown emails so response time doesn't reveal whether the account exists.
      const ok = verifyPassword(password, user?.passwordHash ?? hashPassword("unused"))
      return user && ok ? publicUser(user) : undefined
    },

    create(input: { email: string; password: string; name: string }) {
      const key = input.email.toLowerCase()
      if (byEmail.has(key)) return { error: "email_taken" as const }
      const user: MockUser = { sub: `mock-user-${randomUUID()}`, email: input.email, email_verified: false, name: input.name }
      add(user, input.password)
      return { user }
    },
  }
}
