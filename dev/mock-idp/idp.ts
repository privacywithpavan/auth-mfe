/**
 * Mock of the in-house IdP API. Started by ./server.ts (`npm run mock-idp`) and
 * in-process by tests. Never deploy this.
 *
 * The BFF calls these server-to-server with HTTP Basic client auth:
 *   POST /api/login     { email, password }        → 200 tokens | 401 invalid_credentials | 423 locked
 *   POST /api/register  { email, password, name }  → 201 tokens | 409 email_taken | 400 weak_password
 *   POST /api/logout    { refresh_token }          → 204
 *   POST /token         grant_type=refresh_token   (standard OAuth refresh, from oauth2-mock-server)
 *   GET  /jwks, /.well-known/openid-configuration, /userinfo
 *
 * Seeded users: alice@example.com / bob@example.com, password "password123".
 */
import { randomUUID } from "node:crypto"
import type { ServerResponse } from "node:http"
import { Events, OAuth2Server, type AugmentedRequest } from "oauth2-mock-server"

import { createUserDirectory, type MockUser } from "./users"

export type MockIdpOptions = {
  clientId?: string
  clientSecret?: string
  tokenTtlSeconds?: number
  maxFailedLogins?: number
}

export async function createMockIdp({
  clientId = "auth-mfe",
  clientSecret = "dev-client-secret",
  tokenTtlSeconds = 3600,
  maxFailedLogins = 5,
}: MockIdpOptions = {}) {
  const server = new OAuth2Server()
  await server.issuer.keys.generate("RS256")

  const users = createUserDirectory()
  // Refresh token → user. Refresh tokens rotate on every refresh grant.
  const userByRefreshToken = new Map<string, MockUser>()
  const failedLogins = new Map<string, number>()

  async function issueTokens(user: MockUser) {
    const claims = (_header: unknown, payload: Record<string, unknown>) => {
      Object.assign(payload, user, { aud: clientId })
    }
    const refreshToken = randomUUID()
    userByRefreshToken.set(refreshToken, user)
    return {
      token_type: "Bearer",
      expires_in: tokenTtlSeconds,
      access_token: await server.issuer.buildToken({ scopesOrTransform: claims, expiresIn: tokenTtlSeconds }),
      id_token: await server.issuer.buildToken({ scopesOrTransform: claims, expiresIn: tokenTtlSeconds }),
      refresh_token: refreshToken,
    }
  }

  function isClientAuthenticated(req: AugmentedRequest) {
    const [scheme, encoded] = (req.headers.authorization ?? "").split(" ")
    if (scheme !== "Basic" || !encoded) return false
    const [id, secret] = Buffer.from(encoded, "base64").toString("utf8").split(":")
    return id === clientId && secret === clientSecret
  }

  function withClientAuth(handler: (req: AugmentedRequest, res: ServerResponse) => Promise<void> | void) {
    return (req: AugmentedRequest, res: ServerResponse) =>
      isClientAuthenticated(req) ? handler(req, res) : sendJson(res, 401, { error: "invalid_client" })
  }

  server.service.addRoute(
    "POST",
    "/api/login",
    withClientAuth(async (req, res) => {
      const email = stringField(req, "email").toLowerCase()
      if ((failedLogins.get(email) ?? 0) >= maxFailedLogins) {
        return sendJson(res, 423, { error: "locked" })
      }
      const user = users.authenticate(email, stringField(req, "password"))
      if (!user) {
        failedLogins.set(email, (failedLogins.get(email) ?? 0) + 1)
        return sendJson(res, 401, { error: "invalid_credentials" })
      }
      failedLogins.delete(email)
      sendJson(res, 200, await issueTokens(user))
    })
  )

  server.service.addRoute(
    "POST",
    "/api/register",
    withClientAuth(async (req, res) => {
      const email = stringField(req, "email")
      const password = stringField(req, "password")
      const name = stringField(req, "name")
      if (!email.includes("@") || !name) return sendJson(res, 400, { error: "invalid_request" })
      if (password.length < 8) return sendJson(res, 400, { error: "weak_password" })
      const result = users.create({ email, password, name })
      if ("error" in result) return sendJson(res, 409, { error: result.error })
      sendJson(res, 201, await issueTokens(result.user))
    })
  )

  server.service.addRoute(
    "POST",
    "/api/logout",
    withClientAuth((req, res) => {
      userByRefreshToken.delete(stringField(req, "refresh_token"))
      sendJson(res, 204)
    })
  )

  // Standard refresh grant on /token: put the real user's claims in the new tokens.
  server.service.on(Events.BeforeTokenSigning, (token, req) => {
    const refreshToken = req.body.refresh_token
    const user = typeof refreshToken === "string" ? userByRefreshToken.get(refreshToken) : undefined
    if (user) Object.assign(token.payload, user, { aud: clientId })
  })

  server.service.on(Events.BeforeResponse, (response, req) => {
    if (req.body.grant_type !== "refresh_token" || typeof response.body !== "object") return
    const oldToken = String(req.body.refresh_token)
    const user = userByRefreshToken.get(oldToken)
    userByRefreshToken.delete(oldToken)
    if (!user) {
      response.statusCode = 400
      response.body = { error: "invalid_grant" }
      return
    }
    const newToken = randomUUID()
    userByRefreshToken.set(newToken, user)
    response.body.refresh_token = newToken
  })

  server.service.on(Events.BeforeUserinfo, (response, req) => {
    const payload = req.headers.authorization?.replace(/^Bearer /i, "").split(".")[1]
    const sub = payload && JSON.parse(Buffer.from(payload, "base64url").toString("utf8")).sub
    const user = typeof sub === "string" ? users.findBySub(sub) : undefined
    response.body = user ?? { error: "invalid_token" }
    response.statusCode = user ? 200 : 401
  })

  return {
    server,
    /** Starts listening; pass port 0 for a random free port. Resolves to the issuer URL. */
    async start(port: number, host = "localhost") {
      await server.start(port, host)
      return server.issuer.url!
    },
    stop: () => server.stop(),
  }
}

function stringField(req: AugmentedRequest, name: string) {
  const body = req.body as Record<string, unknown> | undefined
  const value = body?.[name]
  return typeof value === "string" ? value : ""
}

function sendJson(res: ServerResponse, status: number, body?: unknown) {
  res.statusCode = status
  res.setHeader("Cache-Control", "no-store")
  if (body === undefined) return void res.end()
  res.setHeader("Content-Type", "application/json")
  res.end(JSON.stringify(body))
}
