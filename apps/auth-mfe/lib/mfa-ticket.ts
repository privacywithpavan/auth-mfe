import type { IdpTokens, IdpUser } from "./idp/types"
import type { KeyValueStore } from "./store"
import { hashToken, randomToken } from "./tokens"

/**
 * A login in progress: a password login waiting for its second factor, or a
 * passkey-first login waiting for its assertion. The browser holds only the random
 * ticket and posts it back with each step, so the login steps don't depend on how a
 * browser treats cookies in iframes.
 */
export type MfaTicket = {
  kind: "password" | "passkey"
  /** The IdP's transaction for this login. Never sent to the browser. */
  idpTransaction: string
  parentOrigin: string
  /** Rate-limit subject. Absent for passkey-first, where the user isn't known yet. */
  email?: string
  hasPasskey: boolean
  /** Set once the second factor passed; the login completes from here after passkey enrollment or skip. */
  verified?: { user: IdpUser; tokens: IdpTokens }
}

type StoredTicket = MfaTicket & { expiresAt: number }

export const MFA_TICKET_TTL_SECONDS = 5 * 60

function ticketKey(ticket: string) {
  return `mfa:${hashToken(ticket)}`
}

export async function mintMfaTicket(store: KeyValueStore, ticket: MfaTicket): Promise<string> {
  const token = randomToken()
  const stored: StoredTicket = { ...ticket, expiresAt: Date.now() + MFA_TICKET_TTL_SECONDS * 1000 }
  await store.set(ticketKey(token), stored, MFA_TICKET_TTL_SECONDS)
  return token
}

/** The ticket, if it exists and was issued for this parent origin. */
export async function readMfaTicket(
  store: KeyValueStore,
  token: string,
  parentOrigin: string
): Promise<MfaTicket | undefined> {
  const stored = await store.get<StoredTicket>(ticketKey(token))
  return stored?.parentOrigin === parentOrigin ? stored : undefined
}

/** Replaces the ticket's contents. Doesn't extend its lifetime. */
export async function updateMfaTicket(store: KeyValueStore, token: string, ticket: MfaTicket) {
  const stored = await store.get<StoredTicket>(ticketKey(token))
  if (!stored) return
  const ttlSeconds = Math.ceil((stored.expiresAt - Date.now()) / 1000)
  if (ttlSeconds > 0) await store.set(ticketKey(token), { ...ticket, expiresAt: stored.expiresAt }, ttlSeconds)
}

/** Burns the ticket. Only one caller gets it, so a login can't complete twice. */
export async function consumeMfaTicket(
  store: KeyValueStore,
  token: string,
  parentOrigin: string
): Promise<MfaTicket | undefined> {
  const stored = await store.take<StoredTicket>(ticketKey(token))
  return stored?.parentOrigin === parentOrigin ? stored : undefined
}
