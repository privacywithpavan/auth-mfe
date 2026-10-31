/**
 * Stand-in chatbot (frontend + backend) for trying the auth MFE end to end.
 * Reference for the real chatbot team; never deploy this.
 *
 *   pnpm dev   (from the repo root, starts this with the auth MFE and the mock IdP)
 *
 * After login the auth MFE sets an HttpOnly `auth_token` cookie on the shared root domain:
 * a short-lived JWT signed by the IdP. This backend has no session of its own; it verifies
 * that JWT against the IdP's JWKS on every request with @auth-mfe/token-verifier. Renewal
 * and logout go from the browser straight to the auth BFF (refreshAuthSession /
 * logoutAuthSession in @auth-mfe/sdk).
 *
 * Settings come from .env.local (see .env.example); the defaults match the mock IdP.
 */
import { existsSync, readFileSync } from "node:fs"
import { createServer } from "node:https"
import type { IncomingMessage, ServerResponse } from "node:http"
import path from "node:path"

import { ensureDevCertificate } from "@auth-mfe/dev-certs"
import { createAuthTokenVerifier } from "@auth-mfe/token-verifier"
import { build } from "esbuild"

// Optional overrides (see .env.example). Shell variables win over the file.
const envFile = path.resolve(import.meta.dirname, "../.env.local")
if (existsSync(envFile)) process.loadEnvFile(envFile)

const CHAT_ORIGIN = process.env.CHAT_ORIGIN ?? "https://chat.localtest.me:4000"
const AUTH_ORIGIN = process.env.AUTH_ORIGIN ?? "https://auth.localtest.me:3000"
const IDP_BASE_URL = (process.env.IDP_BASE_URL ?? "http://localhost:9000").replace(/\/+$/, "")

const here = import.meta.dirname
const { hostname, port } = new URL(CHAT_ORIGIN)

// --- Backend: verify the IdP-signed auth_token cookie ----------------------------------

const verifier = createAuthTokenVerifier({
  issuer: process.env.IDP_ISSUER ?? IDP_BASE_URL,
  jwksUrl: process.env.IDP_JWKS_URL ?? `${IDP_BASE_URL}/jwks`,
  audience: process.env.SESSION_TOKEN_AUDIENCE ?? "chatbot",
  onReject: (error) => console.warn(`[chat-host] auth_token rejected: ${error.message}`),
})

function send(res: ServerResponse, status: number, body?: unknown, headers: Record<string, string> = {}) {
  res.writeHead(status, { "cache-control": "no-store", ...(body === undefined ? {} : { "content-type": "application/json" }), ...headers })
  res.end(body === undefined ? undefined : JSON.stringify(body))
}

async function handleApi(req: IncomingMessage, res: ServerResponse, pathname: string) {
  if (pathname === "/api/me" && req.method === "GET") {
    const user = await verifier.fromCookieHeader(req.headers.cookie)
    return user ? send(res, 200, { user }) : send(res, 401, { error: "unauthenticated" })
  }

  // Any state-changing route you add: authenticate with verifier.fromCookieHeader(), and allow
  // same-origin only. The cookie is sent by every subdomain of the root domain, so SameSite won't stop CSRF.
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

const certificate = ensureDevCertificate({ hostname, dir: path.resolve(here, "../certificates") })

const server = createServer(certificate, async (req, res) => {
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
