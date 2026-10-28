import type { IdpUser } from "./idp/types"
import type { KeyValueStore } from "./store"
import { hashToken, randomToken } from "./tokens"

/**
 * One-time codes the iframe posts to the chatbot, which its backend exchanges
 * server-to-server for the user's identity. Single use, short-lived, and bound
 * to the parent origin the code was issued for.
 */
export type HandoffRecord = {
  /** Store key of the BFF session this code was minted from. */
  sessionKey: string
  user: IdpUser
  parentOrigin: string
  issuedAt: number
}

function handoffKey(code: string) {
  return `handoff:${hashToken(code)}`
}

export async function mintHandoffCode(
  store: KeyValueStore,
  input: { sessionKey: string; user: IdpUser; parentOrigin: string; ttlSeconds: number }
): Promise<string> {
  const code = randomToken()
  const record: HandoffRecord = {
    sessionKey: input.sessionKey,
    user: input.user,
    parentOrigin: input.parentOrigin,
    issuedAt: Date.now(),
  }
  await store.set(handoffKey(code), record, input.ttlSeconds)
  return code
}

/**
 * Redeems a code. The code is burned even when the origin doesn't match, so a
 * leaked code can't be retried against another client.
 */
export async function consumeHandoffCode(
  store: KeyValueStore,
  code: string,
  expectedParentOrigin: string
): Promise<HandoffRecord | undefined> {
  if (!code) return undefined
  const record = await store.take<HandoffRecord>(handoffKey(code))
  if (!record || record.parentOrigin !== expectedParentOrigin) return undefined
  return record
}
