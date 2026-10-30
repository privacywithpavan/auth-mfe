/**
 * Stand-in chatbot (frontend + backend) for trying the auth MFE end to end.
 * Reference for the real chatbot team; never deploy this.
 *
 *   npm run mock-idp   # IdP
 *   npm run dev        # auth MFE on https://auth.localtest.me:3000
 *   npm run chat-host  # this, on https://chat.localtest.me:4000
 *
 * After login the auth MFE sets an HttpOnly `auth_token` cookie on the shared root domain:
 * a short-lived JWT signed by the IdP. This backend has no session of its own; it verifies
 * that JWT against the IdP's JWKS on every request. Renewal and logout go from the browser
 * straight to the auth BFF (refreshAuthSession / logoutAuthSession in the SDK).
 *
 * Reads IDP_ISSUER / IDP_JWKS_URL / SESSION_TOKEN_AUDIENCE from .env.local (falling back to
 * IDP_BASE_URL and the mock IdP's defaults). CHAT_ORIGIN and AUTH_ORIGIN override the defaults.
 */
import { execFileSync } from "node:child_process"
import { existsSync, readdirSync, readFileSync } from "node:fs"
import { createServer } from "node:https"
import type { IncomingMessage, ServerResponse } from "node:http"
import { homedir } from "node:os"
import path from "node:path"

import { build } from "esbuild"
import { createRemoteJWKSet, jwtVerify } from "jose"

const CHAT_ORIGIN = process.env.CHAT_ORIGIN ?? "https://chat.localtest.me:4000"
const AUTH_ORIGIN = process.env.AUTH_ORIGIN ?? "https://auth.localtest.me:3000"
const IDP_BASE_URL = (process.env.IDP_BASE_URL ?? "http://localhost:9000").replace(/\/+$/, "")
const IDP_ISSUER = process.env.IDP_ISSUER ?? IDP_BASE_URL
const IDP_JWKS_URL = process.env.IDP_JWKS_URL ?? `${IDP_BASE_URL}/jwks`
const AUDIENCE = process.env.SESSION_TOKEN_AUDIENCE ?? "chatbot"
const COOKIE = "auth_token"

const here = import.meta.dirname
const root = path.resolve(here, "../..")
const { hostname, port } = new URL(CHAT_ORIGIN)

// --- TLS: a cert from the mkcert CA that `next dev --experimental-https` installed ------

/** Where Next.js caches the mkcert binary it downloads (same lookup as Next's getCacheDirectory). */
function mkcertDir() {
  switch (process.platform) {
    case "darwin":
      return path.join(homedir(), "Library/Caches/mkcert")
    case "win32":
      return path.join(process.env.LOCALAPPDATA ?? path.join(homedir(), "AppData/Local"), "mkcert")
    default:
      return path.join(process.env.XDG_CACHE_HOME ?? path.join(homedir(), ".cache"), "mkcert")
  }
}

function mkcertBinary() {
  const dir = mkcertDir()
  const binary = existsSync(dir) && readdirSync(dir).find((name) => /^mkcert-v.*-(darwin|linux|windows)-/.test(name))
  if (!binary) {
    throw new Error("mkcert not found. Run `npm run dev` once first; it installs mkcert and its local CA.")
  }
  return path.join(dir, binary)
}

function ensureCertificate() {
  const cert = path.join(root, "certificates", `${hostname}.pem`)
  const key = path.join(root, "certificates", `${hostname}-key.pem`)
  if (!existsSync(cert)) {
    execFileSync(mkcertBinary(), ["-cert-file", cert, "-key-file", key, hostname], { stdio: "inherit" })
  }
  return { cert: readFileSync(cert), key: readFileSync(key) }
}

// --- Backend: verify the IdP-signed auth_token cookie ----------------------------------

type ChatUser = { sub: string; email: string; name: string }

const jwks = createRemoteJWKSet(new URL(IDP_JWKS_URL))

function readAuthToken(req: IncomingMessage) {
  return req.headers.cookie?.match(new RegExp(`(?:^|; )${COOKIE}=([^;]+)`))?.[1]
}

/** The signed-in user, or undefined when the cookie is missing, expired or not from our IdP. */
async function currentUser(req: IncomingMessage): Promise<ChatUser | undefined> {
  const token = readAuthToken(req)
  if (!token) return undefined
  try {
    const { payload } = await jwtVerify(token, jwks, {
      issuer: IDP_ISSUER,
      audience: AUDIENCE,
      algorithms: ["RS256"],
      clockTolerance: 30,
    })
    if (typeof payload.sub !== "string" || typeof payload.email !== "string") return undefined
    return { sub: payload.sub, email: payload.email, name: typeof payload.name === "string" ? payload.name : payload.email }
  } catch (error) {
    console.warn(`[chat-host] auth_token rejected: ${(error as Error).message}`)
    return undefined
  }
}

function send(res: ServerResponse, status: number, body?: unknown, headers: Record<string, string> = {}) {
  res.writeHead(status, { "cache-control": "no-store", ...(body === undefined ? {} : { "content-type": "application/json" }), ...headers })
  res.end(body === undefined ? undefined : JSON.stringify(body))
}

async function handleApi(req: IncomingMessage, res: ServerResponse, pathname: string) {
  if (pathname === "/api/me" && req.method === "GET") {
    const user = await currentUser(req)
    return user ? send(res, 200, { user }) : send(res, 401, { error: "unauthenticated" })
  }

  // Any state-changing route you add: authenticate with currentUser(), and allow same-origin
  // only. The cookie is sent by every subdomain of the root domain, so SameSite won't stop CSRF.
  if (req.method !== "GET" && req.headers.origin !== CHAT_ORIGIN) return send(res, 403, { error: "bad_origin" })

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
