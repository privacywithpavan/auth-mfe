import { describe, expect, it } from "vitest"

import { securityHeaders } from "./security-headers"

const options = {
  allowedParentOrigins: ["https://chat.localtest.me:4000", "https://chat.example.com"],
  production: false,
}

describe("securityHeaders", () => {
  it.each(["/login", "/register", "/login/"])("lets allowlisted origins frame %s", (path) => {
    const headers = securityHeaders(path, options)
    expect(headers["Content-Security-Policy"]).toContain(
      "frame-ancestors https://chat.localtest.me:4000 https://chat.example.com;"
    )
    expect(headers["X-Frame-Options"]).toBeUndefined()
  })

  it.each(["/", "/api/session/refresh", "/login-help", "/loginx"])("forbids framing %s", (path) => {
    const headers = securityHeaders(path, options)
    expect(headers["Content-Security-Policy"]).toContain("frame-ancestors 'none'")
    expect(headers["X-Frame-Options"]).toBe("DENY")
  })

  it("adds HSTS only in production", () => {
    expect(securityHeaders("/", options)["Strict-Transport-Security"]).toBeUndefined()
    expect(securityHeaders("/", { ...options, production: true })["Strict-Transport-Security"]).toContain("max-age")
  })
})
