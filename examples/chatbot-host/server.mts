/**
 * Stand-in chatbot (frontend + backend) for trying the auth MFE end to end.
 * Reference for the real chatbot team; never deploy this.
 *
 *   npm run mock-idp   # IdP
 *   npm run dev        # auth MFE on https://auth.localtest.me:3000
 *   npm run chat-host  # this, on https://chat.localtest.me:4000
 *
 * Reads HANDOFF_CLIENT_ID / HANDOFF_CLIENT_SECRET from .env.local (same values the
 * auth MFE expects). CHAT_ORIGIN and AUTH_ORIGIN override the defaults.
 */
import { execFileSync } from "node:child_process"
import { randomBytes } from "node:crypto"
import { existsSync, readdirSync, readFileSync } from "node:fs"
import { createServer, request as httpsRequest } from "node:https"
import type { IncomingMessage, ServerResponse } from "node:http"
import { homedir } from "node:os"
import path from "node:path"

import { build } from "esbuild"

const CHAT_ORIGIN = process.env.CHAT_ORIGIN ?? "https://chat.localtest.me:4000"
const AUTH_ORIGIN = process.env.AUTH_ORIGIN ?? "https://auth.localtest.me:3000"
const CLIENT_ID = process.env.HANDOFF_CLIENT_ID
const CLIENT_SECRET = process.env.HANDOFF_CLIENT_SECRET
const COOKIE = "chat_session"

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error("HANDOFF_CLIENT_ID and HANDOFF_CLIENT_SECRET must be set (run via `npm run chat-host`).")
  process.exit(1)
}

const here = import.meta.dirname
const root = path.resolve(here, "../..")
const { hostname, port } = new URL(CHAT_ORIGIN)

// --- TLS: reuse the mkcert CA that `next dev --experimental-https` installed -----------

function mkcertDir() {
  return process.platform === "darwin"
    ? path.join(homedir(), "Library/Caches/mkcert")
    : path.join(process.env.XDG_CACHE_HOME ?? path.join(homedir(), ".cache"), "mkcert")
}

function caRoot() {
  return process.platform === "darwin"
    ? path.join(homedir(), "Library/Application Support/mkcert")
    : path.join(process.env.XDG_DATA_HOME ?? path.join(homedir(), ".local/share"), "mkcert")
}

function ensureCertificate() {
  const cert = path.join(root, "certificates", `${hostname}.pem`)
  const key = path.join(root, "certificates", `${hostname}-key.pem`)
  if (!existsSync(cert)) {
    const dir = mkcertDir()
    const binary = existsSync(dir) && readdirSync(dir).find((name) => name.startsWith("mkcert"))
    if (!binary) {
      throw new Error("mkcert not found. Run `npm run dev` once first; it installs mkcert and its local CA.")
    }
    execFileSync(path.join(dir, binary), ["-cert-file", cert, "-key-file", key, hostname], { stdio: "inherit" })
  }
  return { cert: readFileSync(cert), key: readFileSync(key) }
}

const authCa = readFileSync(path.join(caRoot(), "rootCA.pem"))

// --- Backend: sessions and the server-to-server calls to the auth BFF -------------------

type ChatUser = { sub: string; email: string; name: string }
type ChatSession = { user: ChatUser; authSessionRef: string; expiresAt: number }
const sessions = new Map<string, ChatSession>()

/** POSTs JSON to the auth BFF with the chatbot backend's client credentials. */
function callAuth(pathname: string, body: unknown): Promise<{ status: number; json: unknown }> {
  const payload = JSON.stringify(body)
  return new Promise((resolve, reject) => {
    const req = httpsRequest(
      new URL(pathname, AUTH_ORIGIN),
      {
        method: "POST",
        ca: authCa,
        auth: `${CLIENT_ID}:${CLIENT_SECRET}`,
        headers: { "content-type": "application/json", "content-length": Buffer.byteLength(payload) },
        timeout: 5000,
      },
      (res) => {
        let text = ""
        res.on("data", (chunk) => (text += chunk))
        res.on("end", () => resolve({ status: res.statusCode ?? 0, json: text ? JSON.parse(text) : undefined }))
      }
    )
    req.on("timeout", () => req.destroy(new Error("auth BFF timed out")))
    req.on("error", reject)
    req.end(payload)
  })
}

function readSessionId(req: IncomingMessage) {
  return req.headers.cookie?.match(new RegExp(`(?:^|; )${COOKIE}=([^;]+)`))?.[1]
}

function currentSession(req: IncomingMessage) {
  const id = readSessionId(req)
  const session = id ? sessions.get(id) : undefined
  if (session && session.expiresAt > Date.now()) return { id: id!, session }
  if (id) sessions.delete(id)
  return undefined
}

async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  let text = ""
  for await (const chunk of req) text += chunk
  try {
    return JSON.parse(text)
  } catch {
    return {}
  }
}

function send(res: ServerResponse, status: number, body?: unknown, headers: Record<string, string> = {}) {
  res.writeHead(status, { "cache-control": "no-store", ...(body === undefined ? {} : { "content-type": "application/json" }), ...headers })
  res.end(body === undefined ? undefined : JSON.stringify(body))
}

const sessionCookie = (value: string, maxAge: number) =>
  `${COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`

async function handleApi(req: IncomingMessage, res: ServerResponse, pathname: string) {
  if (pathname === "/api/me" && req.method === "GET") {
    const current = currentSession(req)
    return current ? send(res, 200, { user: current.session.user }) : send(res, 401, { error: "unauthenticated" })
  }

  // State-changing calls: same-origin only (CSRF).
  if (req.method !== "POST") return send(res, 405, { error: "method_not_allowed" })
  if (req.headers.origin !== CHAT_ORIGIN) return send(res, 403, { error: "bad_origin" })

  if (pathname === "/api/session") {
    const { code } = await readJsonBody(req)
    if (typeof code !== "string") return send(res, 400, { error: "invalid_request" })
    const { status, json } = await callAuth("/api/handoff/exchange", { code, parent_origin: CHAT_ORIGIN })
    if (status !== 200) {
      console.warn(`[chat-host] exchange failed: ${status} ${JSON.stringify(json)}`)
      return send(res, 401, { error: "login_failed" })
    }
    const { user, session_ref, session_expires_at } = json as {
      user: ChatUser
      session_ref: string
      session_expires_at: string
    }
    const id = randomBytes(32).toString("base64url")
    const expiresAt = Date.parse(session_expires_at)
    sessions.set(id, { user: { sub: user.sub, email: user.email, name: user.name }, authSessionRef: session_ref, expiresAt })
    return send(res, 200, { user }, { "set-cookie": sessionCookie(id, Math.floor((expiresAt - Date.now()) / 1000)) })
  }

  if (pathname === "/api/logout") {
    const current = currentSession(req)
    if (current) {
      sessions.delete(current.id)
      await callAuth("/api/handoff/logout", { session_ref: current.session.authSessionRef }).catch((error) =>
        console.warn(`[chat-host] auth logout failed: ${error.message}`)
      )
    }
    return send(res, 204, undefined, { "set-cookie": sessionCookie("", 0) })
  }

  send(res, 404, { error: "not_found" })
}

// --- Frontend --------------------------------------------------------------------------

async function bundleApp() {
  const result = await build({
    entryPoints: [path.join(here, "app.ts")],
    bundle: true,
    format: "esm",
    target: "es2022",
    write: false,
    define: { __AUTH_ORIGIN__: JSON.stringify(AUTH_ORIGIN) },
  })
  return result.outputFiles[0].text
}

const server = createServer(ensureCertificate(), async (req, res) => {
  const { pathname } = new URL(req.url ?? "/", CHAT_ORIGIN)
  try {
    if (pathname.startsWith("/api/")) return await handleApi(req, res, pathname)
    if (pathname === "/app.js") {
      res.writeHead(200, { "content-type": "text/javascript", "cache-control": "no-store" })
      return res.end(await bundleApp()) // rebuilt per request so SDK edits show up on reload
    }
    if (pathname === "/") {
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" })
      return res.end(readFileSync(path.join(here, "index.html")))
    }
    send(res, 404, { error: "not_found" })
  } catch (error) {
    console.error(error)
    send(res, 500, { error: "server_error" })
  }
})

server.listen(Number(port), hostname, () => {
  console.log(`Chatbot host: ${CHAT_ORIGIN} (auth MFE at ${AUTH_ORIGIN})`)
})
