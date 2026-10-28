import "server-only"
import { cookies } from "next/headers"

import { getConfig } from "./config"
import { getIdpClient } from "./idp"
import type { IdpTokens, IdpUser } from "./idp/types"
import { createSession, destroySession, getActiveSession, sessionKey, type Session } from "./session"
import { getStore } from "./store"

/**
 * Cookie-bound wrappers around lib/session.ts. Writing cookies only works in Server
 * Functions and Route Handlers; reading works anywhere, but with Cache Components the
 * read must sit behind <Suspense> in pages.
 */

// __Host- prefix: browser enforces Secure, Path=/ and no Domain, so subdomains can't overwrite it.
export const SESSION_COOKIE = "__Host-auth_session"

async function currentSessionKey(): Promise<string | undefined> {
  const sessionId = (await cookies()).get(SESSION_COOKIE)?.value
  return sessionId ? sessionKey(sessionId) : undefined
}

/** Creates a BFF session and sets its cookie. Returns the session's store key. */
export async function startSession(user: IdpUser, tokens: IdpTokens): Promise<{ key: string; session: Session }> {
  const ttlSeconds = getConfig().SESSION_TTL_SECONDS
  const { sessionId, key, session } = await createSession(getStore(), { user, tokens, ttlSeconds })
  ;(await cookies()).set(SESSION_COOKIE, sessionId, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: ttlSeconds,
  })
  return { key, session }
}

/** The signed-in session with a fresh access token, or undefined. */
export async function getCurrentSession(): Promise<{ key: string; session: Session } | undefined> {
  const key = await currentSessionKey()
  if (!key) return undefined
  const session = await getActiveSession(getStore(), getIdpClient(), key)
  return session ? { key, session } : undefined
}

export async function endSession() {
  const key = await currentSessionKey()
  if (key) await destroySession(getStore(), getIdpClient(), key)
  ;(await cookies()).delete(SESSION_COOKIE)
}
