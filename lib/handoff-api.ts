import { createHash, timingSafeEqual } from "node:crypto"
import { z } from "zod"

import { consumeHandoffCode } from "./handoff"
import type { IdpClient } from "./idp/types"
import { destroySession, readSession } from "./session"
import type { KeyValueStore } from "./store"

/**
 * Server-to-server API for the chatbot backend:
 *   POST /api/handoff/exchange  { code, parent_origin } → { user, session_ref, session_expires_at }
 *   POST /api/handoff/logout    { session_ref }         → 204
 * Both require HTTP Basic auth with HANDOFF_CLIENT_ID / HANDOFF_CLIENT_SECRET.
 * Errors follow OAuth conventions: { error } with 400/401/415.
 */
export type HandoffApiDeps = {
  store: KeyValueStore
  idp: IdpClient
  clientId: string
  clientSecret: string
}

const exchangeBody = z.object({ code: z.string().min(1).max(256), parent_origin: z.string().min(1).max(512) })
const logoutBody = z.object({ session_ref: z.string().min(1).max(256) })

function json(body: unknown, status = 200, extraHeaders: Record<string, string> = {}) {
  return Response.json(body, {
    status,
    headers: { "Cache-Control": "no-store", Pragma: "no-cache", ...extraHeaders },
  })
}

function digest(value: string) {
  return createHash("sha256").update(value).digest()
}

/** Constant-time check of the Basic credentials (hashing first equalizes lengths). */
function isAuthorizedClient(request: Request, deps: HandoffApiDeps) {
  const [scheme, encoded] = (request.headers.get("authorization") ?? "").split(" ")
  if (scheme?.toLowerCase() !== "basic" || !encoded) return false
  const decoded = Buffer.from(encoded, "base64").toString("utf8")
  const separator = decoded.indexOf(":")
  if (separator < 0) return false
  const idOk = timingSafeEqual(digest(decoded.slice(0, separator)), digest(deps.clientId))
  const secretOk = timingSafeEqual(digest(decoded.slice(separator + 1)), digest(deps.clientSecret))
  return idOk && secretOk
}

async function readJson<T>(request: Request, schema: z.ZodType<T>): Promise<T | Response> {
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) {
    return json({ error: "invalid_request", error_description: "Content-Type must be application/json" }, 415)
  }
  const parsed = schema.safeParse(await request.json().catch(() => undefined))
  return parsed.success ? parsed.data : json({ error: "invalid_request" }, 400)
}

const unauthorized = () => json({ error: "invalid_client" }, 401, { "WWW-Authenticate": 'Basic realm="auth-mfe"' })

export async function handleExchange(request: Request, deps: HandoffApiDeps): Promise<Response> {
  if (!isAuthorizedClient(request, deps)) return unauthorized()
  const body = await readJson(request, exchangeBody)
  if (body instanceof Response) return body

  const record = await consumeHandoffCode(deps.store, body.code, body.parent_origin)
  // The user may have logged out between login and exchange.
  const session = record && (await readSession(deps.store, record.sessionKey))
  if (!record || !session) return json({ error: "invalid_grant" }, 400)

  console.info(`[handoff] exchanged sub=${record.user.sub} origin=${record.parentOrigin}`)
  const { sub, email, name, emailVerified } = session.user
  return json({
    user: { sub, email, name, email_verified: emailVerified },
    session_ref: record.sessionKey,
    session_expires_at: new Date(session.expiresAt).toISOString(),
  })
}

export async function handleLogout(request: Request, deps: HandoffApiDeps): Promise<Response> {
  if (!isAuthorizedClient(request, deps)) return unauthorized()
  const body = await readJson(request, logoutBody)
  if (body instanceof Response) return body
  // Only session store keys are valid refs; anything else is a no-op.
  if (body.session_ref.startsWith("session:")) await destroySession(deps.store, deps.idp, body.session_ref)
  // Idempotent: unknown or already-ended sessions also return 204.
  return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } })
}
