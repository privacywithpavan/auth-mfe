import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT, type GenerateKeyPairResult, type JWK } from "jose"
import { beforeAll, describe, expect, it } from "vitest"

import { createAuthTokenVerifier, readAuthTokenCookies } from "./index"

const ISSUER = "https://idp.example.com"
const AUDIENCE = "chatbot"

let privateKey: GenerateKeyPairResult["privateKey"]
let jwk: JWK

beforeAll(async () => {
  const pair = await generateKeyPair("RS256")
  privateKey = pair.privateKey
  jwk = { ...(await exportJWK(pair.publicKey)), kid: "k1", alg: "RS256" }
})

function sign(claims: Record<string, unknown> = {}, { exp = "10m", key = privateKey } = {}) {
  return new SignJWT({ iss: ISSUER, aud: AUDIENCE, sub: "user-alice", email: "alice@example.com", name: "Alice", ...claims })
    .setProtectedHeader({ alg: "RS256", kid: "k1" })
    .setIssuedAt()
    .setExpirationTime(exp)
    .sign(key)
}

function verifier(rejections: Error[] = []) {
  return createAuthTokenVerifier({
    issuer: ISSUER,
    audience: AUDIENCE,
    jwks: createLocalJWKSet({ keys: [jwk] }),
    onReject: (error) => rejections.push(error),
  })
}

describe("createAuthTokenVerifier", () => {
  it("returns the user from a valid token", async () => {
    expect(await verifier().verify(await sign())).toEqual({ sub: "user-alice", email: "alice@example.com", name: "Alice" })
  })

  it("falls back to the email when there's no name", async () => {
    expect(await verifier().verify(await sign({ name: undefined }))).toMatchObject({ name: "alice@example.com" })
  })

  it("rejects another audience, another issuer, an expired token and a foreign key", async () => {
    const rejections: Error[] = []
    const other = await generateKeyPair("RS256")
    const tokens = [
      await sign({ aud: "billing" }),
      await sign({ iss: "https://evil.example.com" }),
      await sign({}, { exp: "-1m" }),
      await sign({}, { key: other.privateKey }),
    ]
    for (const token of tokens) expect(await verifier(rejections).verify(token)).toBeUndefined()
    expect(rejections).toHaveLength(4)
  })

  it("rejects a token without an email", async () => {
    expect(await verifier().verify(await sign({ email: undefined }))).toBeUndefined()
  })

  it("skips a planted auth_token and accepts the valid one next to it", async () => {
    const header = `theme=dark; auth_token=planted.not.valid; auth_token=${await sign()}`
    expect(await verifier().fromCookieHeader(header)).toMatchObject({ sub: "user-alice" })
  })

  it("returns undefined without the cookie", async () => {
    expect(await verifier().fromCookieHeader(undefined)).toBeUndefined()
    expect(await verifier().fromCookieHeader("theme=dark")).toBeUndefined()
  })
})

describe("readAuthTokenCookies", () => {
  it("reads every auth_token value and ignores similar names", () => {
    expect(readAuthTokenCookies("x_auth_token=a; auth_token=b;auth_token=c ; auth_token=")).toEqual(["b", "c"])
  })
})
