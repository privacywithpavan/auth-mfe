import type { IdpClient, IdpTokens, IdpUser } from "./idp/types"
import type { KeyValueStore } from "./store"
import { hashToken, randomToken } from "./tokens"

/**
 * Server-side BFF sessions. The browser holds only the opaque session id (see
 * session-cookie.ts); IdP tokens never leave the server.
 */
export type Session = {
  user: IdpUser
  tokens: IdpTokens
  createdAt: number
  expiresAt: number
}

/** Refresh the access token when it has less than this long to live. */
const REFRESH_LEEWAY_MS = 60_000

/** Store key for a session id. Also the stable reference handoff codes point at. */
export function sessionKey(sessionId: string) {
  return `session:${hashToken(sessionId)}`
}

export async function createSession(
  store: KeyValueStore,
  input: { user: IdpUser; tokens: IdpTokens; ttlSeconds: number }
): Promise<{ sessionId: string; key: string; session: Session }> {
  const sessionId = randomToken()
  const createdAt = Date.now()
  const session: Session = {
    user: input.user,
    tokens: input.tokens,
    createdAt,
    expiresAt: createdAt + input.ttlSeconds * 1000,
  }
  const key = sessionKey(sessionId)
  await store.set(key, session, input.ttlSeconds)
  return { sessionId, key, session }
}

export async function readSession(store: KeyValueStore, key: string): Promise<Session | undefined> {
  const session = await store.get<Session>(key)
  return session && session.expiresAt > Date.now() ? session : undefined
}

/**
 * Returns the session with a usable access token, refreshing it through the IdP
 * when close to expiry. A rejected refresh ends the session.
 */
export async function getActiveSession(
  store: KeyValueStore,
  idp: IdpClient,
  key: string
): Promise<Session | undefined> {
  const session = await readSession(store, key)
  if (!session) return undefined
  if (session.tokens.expiresAt - Date.now() > REFRESH_LEEWAY_MS) return session
  if (!session.tokens.refreshToken) {
    await store.delete(key)
    return undefined
  }

  const result = await idp.refresh(session.tokens.refreshToken)
  if (!result.ok) {
    // IdP outage: keep the session while the current access token is still valid.
    if (result.error === "unavailable" && session.tokens.expiresAt > Date.now()) return session
    await store.delete(key)
    return undefined
  }

  const refreshed: Session = { ...session, user: result.user, tokens: result.tokens }
  const ttlSeconds = Math.ceil((session.expiresAt - Date.now()) / 1000)
  await store.set(key, refreshed, ttlSeconds)
  return refreshed
}

export async function destroySession(store: KeyValueStore, idp: IdpClient, key: string) {
  const session = await store.take<Session>(key)
  if (session) await idp.logout(session.tokens)
}
