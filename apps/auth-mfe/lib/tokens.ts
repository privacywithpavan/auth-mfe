import { createHash, randomBytes } from "node:crypto"

/** 256-bit random value, URL-safe. Used for session ids and MFA tickets. */
export function randomToken(): string {
  return randomBytes(32).toString("base64url")
}

/**
 * Store keys are hashes of the secret, so a leaked store dump can't be replayed
 * as cookies or MFA tickets.
 */
export function hashToken(token: string): string {
  return createHash("sha256").update(token).digest("base64url")
}
