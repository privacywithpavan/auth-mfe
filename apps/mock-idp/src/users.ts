import { randomBytes, randomUUID, scryptSync, timingSafeEqual } from "node:crypto"
import type { WebAuthnCredential } from "@simplewebauthn/server"

export type MockUser = {
  sub: string
  email: string
  email_verified: boolean
  name: string
}

type StoredUser = MockUser & { passwordHash: string; passkeys: WebAuthnCredential[] }

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
    byEmail.set(user.email.toLowerCase(), { ...user, passwordHash: hashPassword(password), passkeys: [] })
  }

  add({ sub: "mock-user-alice", email: "alice@example.com", email_verified: true, name: "Alice Example" }, SEED_PASSWORD)
  add({ sub: "mock-user-bob", email: "bob@example.com", email_verified: true, name: "Bob Example" }, SEED_PASSWORD)

  function storedBySub(sub: string) {
    for (const user of byEmail.values()) if (user.sub === sub) return user
  }

  return {
    findBySub(sub: string): MockUser | undefined {
      const user = storedBySub(sub)
      return user && publicUser(user)
    },

    passkeysOf(sub: string): WebAuthnCredential[] {
      return storedBySub(sub)?.passkeys ?? []
    },

    addPasskey(sub: string, credential: WebAuthnCredential) {
      storedBySub(sub)?.passkeys.push(credential)
    },

    /** The passkey with this credential id and its owner, for passkey-first logins. */
    findPasskey(credentialId: string): { user: MockUser; credential: WebAuthnCredential } | undefined {
      for (const user of byEmail.values()) {
        const credential = user.passkeys.find((passkey) => passkey.id === credentialId)
        if (credential) return { user: publicUser(user), credential }
      }
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
