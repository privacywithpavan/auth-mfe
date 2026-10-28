import { describe, expect, it } from "vitest"

import { parseConfig } from "./config"

const valid = {
  APP_ORIGIN: "https://auth.localtest.me:3000",
  IDP_BASE_URL: "http://localhost:9000",
  IDP_CLIENT_ID: "auth-mfe",
  IDP_CLIENT_SECRET: "secret",
  ALLOWED_PARENT_ORIGINS: "https://chat.localtest.me:4000, https://other.localtest.me",
  HANDOFF_CLIENT_ID: "chatbot",
  HANDOFF_CLIENT_SECRET: "x".repeat(32),
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
    expect(config.HANDOFF_CODE_TTL_SECONDS).toBe(60)
  })

  it("rejects parent origins with a path or trailing slash", () => {
    expect(() =>
      parseConfig({ ...valid, ALLOWED_PARENT_ORIGINS: "https://chat.localtest.me/" })
    ).toThrow(/bare origin/)
  })

  it("rejects a short handoff secret", () => {
    expect(() => parseConfig({ ...valid, HANDOFF_CLIENT_SECRET: "short" })).toThrow(
      /HANDOFF_CLIENT_SECRET/
    )
  })

  it("requires https in production", () => {
    expect(() => parseConfig({ ...valid, NODE_ENV: "production" })).toThrow(
      /http:\/\/localhost:9000 must use https/
    )
  })
})
