import { describe, expect, it } from "vitest"

import { parseAllowedParentOrigin, parseNonce } from "./origins"

const allowlist = ["https://chat.localtest.me:4000", "https://chat.example.com"]

describe("parseAllowedParentOrigin", () => {
  it("accepts an exact allowlisted origin", () => {
    expect(parseAllowedParentOrigin("https://chat.example.com", allowlist)).toBe("https://chat.example.com")
  })

  it.each([
    "https://chat.example.com/",
    "https://chat.example.com/path",
    "https://chat.example.com.evil.com",
    "https://evil.com#https://chat.example.com",
    "http://chat.example.com",
    "https://CHAT.example.com",
    "https://chat.localtest.me",
    "null",
    "",
    "*",
  ])("rejects %s", (value) => {
    expect(parseAllowedParentOrigin(value, allowlist)).toBeUndefined()
  })

  it("rejects non-strings", () => {
    expect(parseAllowedParentOrigin(["https://chat.example.com"], allowlist)).toBeUndefined()
    expect(parseAllowedParentOrigin(undefined, allowlist)).toBeUndefined()
  })
})

describe("parseNonce", () => {
  it("accepts URL-safe values of reasonable length", () => {
    expect(parseNonce("abcdefghijklmnop")).toBe("abcdefghijklmnop")
  })

  it.each(["short", "a".repeat(129), "has spaces in it!!", "<script>alert(1)</script>"])("rejects %s", (value) => {
    expect(parseNonce(value)).toBeUndefined()
  })
})
