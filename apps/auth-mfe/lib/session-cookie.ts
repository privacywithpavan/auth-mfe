import "server-only"
import { AUTH_TOKEN_COOKIE } from "@auth-mfe/token-verifier"
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
 *
 * Two cookies:
 * - __Host-auth_session: the BFF session id, for this app only. Lets /api/session/*
 *   refresh tokens and log out.
 * - auth_token: the IdP's short-lived session JWT, scoped to SESSION_COOKIE_DOMAIN so the
 *   chatbot's backend receives it and verifies it against the IdP's JWKS.
 */

// __Host- prefix: browser enforces Secure, Path=/ and no Domain, so subdomains can't overwrite it.
export const SESSION_COOKIE = "__Host-auth_session"

async function currentSessionKey(): Promise<string | undefined> {
  const sessionId = (await cookies()).get(SESSION_COOKIE)?.value
  return sessionId ? sessionKey(sessionId) : undefined
}

/** Creates a BFF session and sets both cookies. */
export async function startSession(user: IdpUser, tokens: IdpTokens) {
  const ttlSeconds = getConfig().SESSION_TTL_SECONDS
  const { sessionId } = await createSession(getStore(), { user, tokens, ttlSeconds })
  ;(await cookies()).set(SESSION_COOKIE, sessionId, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    maxAge: ttlSeconds,
  })
  await setAuthTokenCookie(tokens)
}

/** Sets auth_token to the session JWT; it expires with the JWT. */
export async function setAuthTokenCookie(tokens: IdpTokens) {
  const maxAge = Math.floor((tokens.sessionTokenExpiresAt - Date.now()) / 1000)
  if (maxAge <= 0) return clearAuthTokenCookie()
  ;(await cookies()).set(AUTH_TOKEN_COOKIE, tokens.sessionToken, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    domain: getConfig().SESSION_COOKIE_DOMAIN,
    maxAge,
  })
}

/** Deletes auth_token. Domain and path must match how it was set. */
export async function clearAuthTokenCookie() {
  ;(await cookies()).delete({
    name: AUTH_TOKEN_COOKIE,
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/",
    domain: getConfig().SESSION_COOKIE_DOMAIN,
  })
}

/** The signed-in session with fresh tokens, or undefined. */
export async function getCurrentSession(): Promise<{ key: string; session: Session } | undefined> {
  const key = await currentSessionKey()
  if (!key) return undefined
  const session = await getActiveSession(getStore(), getIdpClient(), key)
  return session ? { key, session } : undefined
}

export async function endSession() {
  const key = await currentSessionKey()
  if (key) await destroySession(getStore(), getIdpClient(), key)
  // Browsers ignore a __Host- cookie (including its deletion) without Secure.
  ;(await cookies()).delete({ name: SESSION_COOKIE, httpOnly: true, secure: true, sameSite: "lax", path: "/" })
  await clearAuthTokenCookie()
}
