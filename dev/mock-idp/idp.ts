/**
 * Mock of the in-house IdP API. Started by ./server.ts (`npm run mock-idp`) and
 * in-process by tests. Never deploy this.
 *
 * The BFF calls these server-to-server with HTTP Basic client auth:
 *   POST /api/login     { email, password }        → 200 { mfa_required, mfa_token, has_passkey } | 401 invalid_credentials | 423 locked
 *                                                    (200 tokens directly when created with requireMfa: false)
 *   POST /api/register  { email, password, name }  → 201 tokens | 409 email_taken | 400 weak_password
 *   POST /api/logout    { refresh_token }          → 204
 *   POST /token         grant_type=refresh_token   (standard OAuth refresh, from oauth2-mock-server)
 *
 * Second factor and passkeys. A transaction is the login in progress (5 min); passkey
 * creation is only allowed once its second factor passed:
 *   POST /api/mfa/otp/send                    { mfa_token }            → 204 (code goes to onOtp, logged by default)
 *   POST /api/mfa/otp/verify                  { mfa_token, code }      → 200 tokens | 400 invalid_code | 400 invalid_grant
 *   POST /api/passkeys/registration/options   { mfa_token }            → 200 { options } | 403 invalid_grant
 *   POST /api/passkeys/registration/verify    { mfa_token, response }  → 204 | 400 passkey_failed
 *   POST /api/passkeys/authentication/options { mfa_token? }           → 200 { transaction, options }
 *   POST /api/passkeys/authentication/verify  { transaction, response } → 200 tokens | 400 passkey_failed
 * Without mfa_token, authentication starts a passkey-first login (discoverable credentials).
 *   GET  /jwks, /.well-known/openid-configuration, /userinfo
 *
 * Seeded users: alice@example.com / bob@example.com, password "password123".
 */
import { randomInt, randomUUID, timingSafeEqual } from "node:crypto"
import type { ServerResponse } from "node:http"
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server"
import { Events, OAuth2Server, type AugmentedRequest } from "oauth2-mock-server"

import { createUserDirectory, type MockUser } from "./users"

export type MockIdpOptions = {
  clientId?: string
  clientSecret?: string
  tokenTtlSeconds?: number
  maxFailedLogins?: number
  /** Password logins need a second factor (default true). */
  requireMfa?: boolean
  /** WebAuthn relying party: the auth MFE's host, and the origin its pages are served from. */
  rpId?: string
  rpName?: string
  expectedOrigin?: string
  /** Receives emailed one-time codes. Defaults to logging them. */
  onOtp?: (email: string, code: string) => void
  maxOtpAttempts?: number
}

/** A login in progress. `user` is unknown for passkey-first until the assertion verifies. */
type Transaction = {
  kind: "mfa" | "passkey"
  user?: MockUser
  otp?: { code: string; expiresAt: number }
  otpAttempts: number
  /** The second factor passed; the user may now create a passkey. */
  verified: boolean
  /** Pending WebAuthn challenge. Cleared before verifying so it can't be replayed. */
  challenge?: string
  expiresAt: number
}

const TRANSACTION_TTL_MS = 5 * 60_000
const OTP_TTL_MS = 5 * 60_000

export async function createMockIdp({
  clientId = "auth-mfe",
  clientSecret = "dev-client-secret",
  tokenTtlSeconds = 3600,
  maxFailedLogins = 5,
  requireMfa = true,
  rpId = "auth.localtest.me",
  rpName = "Chatbot",
  expectedOrigin = "https://auth.localtest.me:3000",
  onOtp = (email, code) => console.log(`[mock-idp] one-time code for ${email}: ${code}`),
  maxOtpAttempts = 5,
}: MockIdpOptions = {}) {
  const server = new OAuth2Server()
  await server.issuer.keys.generate("RS256")

  const users = createUserDirectory()
  // Refresh token → user. Refresh tokens rotate on every refresh grant.
  const userByRefreshToken = new Map<string, MockUser>()
  const failedLogins = new Map<string, number>()
  const transactions = new Map<string, Transaction>()

  function startTransaction(kind: Transaction["kind"], user?: MockUser) {
    const id = randomUUID()
    transactions.set(id, { kind, user, otpAttempts: 0, verified: false, expiresAt: Date.now() + TRANSACTION_TTL_MS })
    return id
  }

  function liveTransaction(id: string) {
    const transaction = transactions.get(id)
    if (transaction && transaction.expiresAt > Date.now()) return transaction
    transactions.delete(id)
  }

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
      if (!requireMfa) return sendJson(res, 200, await issueTokens(user))
      sendJson(res, 200, {
        mfa_required: true,
        mfa_token: startTransaction("mfa", user),
        has_passkey: users.passkeysOf(user.sub).length > 0,
      })
    })
  )

  /** The password login's transaction, if it's still open. */
  function mfaTransaction(req: AugmentedRequest) {
    const transaction = liveTransaction(stringField(req, "mfa_token"))
    return transaction?.kind === "mfa" && transaction.user ? (transaction as Transaction & { user: MockUser }) : undefined
  }

  server.service.addRoute(
    "POST",
    "/api/mfa/otp/send",
    withClientAuth((req, res) => {
      const transaction = mfaTransaction(req)
      if (!transaction || transaction.verified) return sendJson(res, 400, { error: "invalid_grant" })
      const code = String(randomInt(0, 1_000_000)).padStart(6, "0")
      transaction.otp = { code, expiresAt: Date.now() + OTP_TTL_MS }
      onOtp(transaction.user.email, code)
      sendJson(res, 204)
    })
  )

  server.service.addRoute(
    "POST",
    "/api/mfa/otp/verify",
    withClientAuth(async (req, res) => {
      const transaction = mfaTransaction(req)
      if (!transaction || transaction.verified) return sendJson(res, 400, { error: "invalid_grant" })
      const { otp } = transaction
      const code = Buffer.from(stringField(req, "code"))
      const matches = otp && otp.expiresAt > Date.now() && code.length === otp.code.length && timingSafeEqual(code, Buffer.from(otp.code))
      if (!matches) {
        transaction.otpAttempts += 1
        if (transaction.otpAttempts >= maxOtpAttempts) {
          transactions.delete(stringField(req, "mfa_token"))
          return sendJson(res, 400, { error: "invalid_grant" })
        }
        return sendJson(res, 400, { error: "invalid_code" })
      }
      transaction.otp = undefined
      transaction.verified = true
      sendJson(res, 200, await issueTokens(transaction.user))
    })
  )

  server.service.addRoute(
    "POST",
    "/api/passkeys/registration/options",
    withClientAuth(async (req, res) => {
      const transaction = mfaTransaction(req)
      // Creating a passkey needs a passed second factor, never just the password.
      if (!transaction?.verified) return sendJson(res, 403, { error: "invalid_grant" })
      const { user } = transaction
      const options = await generateRegistrationOptions({
        rpName,
        rpID: rpId,
        userName: user.email,
        userDisplayName: user.name,
        userID: new TextEncoder().encode(user.sub),
        attestationType: "none",
        excludeCredentials: users.passkeysOf(user.sub).map(({ id, transports }) => ({ id, transports })),
        authenticatorSelection: { residentKey: "required", userVerification: "required" },
      })
      transaction.challenge = options.challenge
      sendJson(res, 200, { options })
    })
  )

  server.service.addRoute(
    "POST",
    "/api/passkeys/registration/verify",
    withClientAuth(async (req, res) => {
      const transaction = mfaTransaction(req)
      const expectedChallenge = transaction?.challenge
      if (!transaction?.verified || !expectedChallenge) return sendJson(res, 400, { error: "invalid_grant" })
      transaction.challenge = undefined
      try {
        const { verified, registrationInfo } = await verifyRegistrationResponse({
          response: objectField(req, "response") as unknown as RegistrationResponseJSON,
          expectedChallenge,
          expectedOrigin,
          expectedRPID: rpId,
          requireUserVerification: true,
        })
        if (!verified) throw new Error("not verified")
        users.addPasskey(transaction.user.sub, registrationInfo.credential)
        sendJson(res, 204)
      } catch (error) {
        console.warn(`[mock-idp] passkey registration rejected: ${(error as Error).message}`)
        sendJson(res, 400, { error: "passkey_failed" })
      }
    })
  )

  server.service.addRoute(
    "POST",
    "/api/passkeys/authentication/options",
    withClientAuth(async (req, res) => {
      let id = stringField(req, "mfa_token")
      let allowCredentials: Parameters<typeof generateAuthenticationOptions>[0]["allowCredentials"]
      if (id) {
        const transaction = mfaTransaction(req)
        if (!transaction || transaction.verified) return sendJson(res, 400, { error: "invalid_grant" })
        allowCredentials = users.passkeysOf(transaction.user.sub).map(({ id, transports }) => ({ id, transports }))
        if (allowCredentials.length === 0) return sendJson(res, 400, { error: "invalid_request" })
      } else {
        id = startTransaction("passkey")
      }
      const options = await generateAuthenticationOptions({ rpID: rpId, allowCredentials, userVerification: "required" })
      transactions.get(id)!.challenge = options.challenge
      sendJson(res, 200, { transaction: id, options })
    })
  )

  server.service.addRoute(
    "POST",
    "/api/passkeys/authentication/verify",
    withClientAuth(async (req, res) => {
      const id = stringField(req, "transaction")
      const transaction = liveTransaction(id)
      const expectedChallenge = transaction?.challenge
      if (!transaction || transaction.verified || !expectedChallenge) {
        return sendJson(res, 400, { error: "invalid_grant" })
      }
      transaction.challenge = undefined
      // A passkey-first transaction is single use either way.
      if (transaction.kind === "passkey") transactions.delete(id)

      const response = objectField(req, "response") as unknown as AuthenticationResponseJSON
      const found = typeof response.id === "string" ? users.findPasskey(response.id) : undefined
      try {
        if (!found) throw new Error("unknown credential")
        // Second factor: must be this user's passkey. Passkey-first: the user handle must match its owner.
        if (transaction.user && transaction.user.sub !== found.user.sub) throw new Error("credential belongs to another user")
        const userHandle = response.response?.userHandle
        if (userHandle && userHandle !== Buffer.from(found.user.sub).toString("base64url")) {
          throw new Error("user handle mismatch")
        }
        const { verified, authenticationInfo } = await verifyAuthenticationResponse({
          response,
          expectedChallenge,
          expectedOrigin,
          expectedRPID: rpId,
          credential: found.credential,
          requireUserVerification: true,
        })
        if (!verified) throw new Error("not verified")
        found.credential.counter = authenticationInfo.newCounter
      } catch (error) {
        console.warn(`[mock-idp] passkey authentication rejected: ${(error as Error).message}`)
        return sendJson(res, 400, { error: "passkey_failed" })
      }
      transaction.verified = true
      sendJson(res, 200, await issueTokens(found.user))
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

function objectField(req: AugmentedRequest, name: string): Record<string, unknown> {
  const body = req.body as Record<string, unknown> | undefined
  const value = body?.[name]
  return typeof value === "object" && value !== null ? (value as Record<string, unknown>) : {}
}

function sendJson(res: ServerResponse, status: number, body?: unknown) {
  res.statusCode = status
  res.setHeader("Cache-Control", "no-store")
  if (body === undefined) return void res.end()
  res.setHeader("Content-Type", "application/json")
  res.end(JSON.stringify(body))
}
