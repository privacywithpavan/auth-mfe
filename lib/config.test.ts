import { describe, expect, it } from "vitest"

import { parseConfig } from "./config"

const valid = {
  APP_ORIGIN: "https://auth.localtest.me:3000",
  IDP_BASE_URL: "http://localhost:9000",
  IDP_CLIENT_ID: "auth-mfe",
  IDP_CLIENT_SECRET: "secret",
  ALLOWED_PARENT_ORIGINS: "https://chat.localtest.me:4000, https://other.localtest.me",
  SESSION_COOKIE_DOMAIN: "localtest.me",
}

describe("parseConfig", () => {
  it("applies defaults and splits the origin allowlist", () => {
    const config = parseConfig(valid)
    expect(config.ALLOWED_PARENT_ORIGINS).toEqual([
      "https://chat.localtest.me:4000",
      "https://other.localtest.me",
    ])
    expect(config.IDP_ISSUER).toBe("http://localhost:9000")
    expect(config.IDP_JWKS_URL).toBe("http://localhost:9000/jwks")
    expect(config.SESSION_TOKEN_AUDIENCE).toBe("chatbot")
  })

  it("rejects parent origins with a path or trailing slash", () => {
    expect(() =>
      parseConfig({ ...valid, ALLOWED_PARENT_ORIGINS: "https://chat.localtest.me/" })
    ).toThrow(/bare origin/)
  })

  it("rejects a cookie domain with a scheme, port or leading dot", () => {
    for (const value of ["https://localtest.me", "localtest.me:3000", ".localtest.me", "localhost"]) {
      expect(() => parseConfig({ ...valid, SESSION_COOKIE_DOMAIN: value })).toThrow(/bare domain/)
    }
  })

  it("requires the app and every parent origin to be on the cookie domain", () => {
    expect(() =>
      parseConfig({ ...valid, ALLOWED_PARENT_ORIGINS: "https://chat.localtest.me:4000, https://chat.example.com" })
    ).toThrow(/https:\/\/chat.example.com must be on SESSION_COOKIE_DOMAIN/)
    expect(() => parseConfig({ ...valid, SESSION_COOKIE_DOMAIN: "chat.localtest.me" })).toThrow(
      /https:\/\/auth.localtest.me:3000 must be on SESSION_COOKIE_DOMAIN/
    )
    // A look-alike suffix isn't a subdomain.
    expect(() => parseConfig({ ...valid, ALLOWED_PARENT_ORIGINS: "https://evil-localtest.me" })).toThrow(
      /must be on SESSION_COOKIE_DOMAIN/
    )
  })

  it("requires https in production", () => {
    expect(() => parseConfig({ ...valid, NODE_ENV: "production" })).toThrow(
      /http:\/\/localhost:9000 must use https/
    )
  })
})
