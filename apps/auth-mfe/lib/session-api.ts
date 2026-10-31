import type { IdpTokens } from "./idp/types"
import type { Session } from "./session"

/**
 * Browser-facing session API for the chatbot page, called with credentials from an
 * allowlisted parent origin (same site, so the BFF's SameSite=Lax cookies are sent):
 *   POST /api/session/refresh → 200 { user, expires_at } and a fresh auth_token cookie | 401 unauthenticated
 *   POST /api/session/logout  → 204, ends the session and clears both cookies
 * SameSite doesn't stop sibling subdomains, so every request must carry an allowlisted Origin.
 */
export type SessionApiDeps = {
  allowedParentOrigins: readonly string[]
  getCurrentSession: () => Promise<{ session: Session } | undefined>
  setAuthTokenCookie: (tokens: IdpTokens) => Promise<void>
  clearAuthTokenCookie: () => Promise<void>
  endSession: () => Promise<void>
}

function allowedOrigin(request: Request, deps: SessionApiDeps) {
  const origin = request.headers.get("origin")
  return origin && deps.allowedParentOrigins.includes(origin) ? origin : undefined
}

function corsHeaders(origin: string): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Cache-Control": "no-store",
    Vary: "Origin",
  }
}

const forbidden = () => Response.json({ error: "forbidden_origin" }, { status: 403, headers: { Vary: "Origin" } })

export function handlePreflight(request: Request, deps: SessionApiDeps): Response {
  const origin = allowedOrigin(request, deps)
  if (!origin) return forbidden()
  return new Response(null, {
    status: 204,
    headers: { ...corsHeaders(origin), "Access-Control-Allow-Methods": "POST", "Access-Control-Max-Age": "600" },
  })
}

export async function handleRefresh(request: Request, deps: SessionApiDeps): Promise<Response> {
  const origin = allowedOrigin(request, deps)
  if (!origin) return forbidden()

  const current = await deps.getCurrentSession()
  if (!current) {
    await deps.clearAuthTokenCookie()
    return Response.json({ error: "unauthenticated" }, { status: 401, headers: corsHeaders(origin) })
  }

  const { user, tokens } = current.session
  await deps.setAuthTokenCookie(tokens)
  return Response.json(
    {
      user: { sub: user.sub, email: user.email, name: user.name },
      expires_at: new Date(tokens.sessionTokenExpiresAt).toISOString(),
    },
    { headers: corsHeaders(origin) }
  )
}

export async function handleLogout(request: Request, deps: SessionApiDeps): Promise<Response> {
  const origin = allowedOrigin(request, deps)
  if (!origin) return forbidden()
  // Idempotent: no session still clears the cookies and returns 204.
  await deps.endSession()
  return new Response(null, { status: 204, headers: corsHeaders(origin) })
}
