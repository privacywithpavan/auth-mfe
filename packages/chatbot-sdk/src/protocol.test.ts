import { describe, expect, it } from "vitest"

import { envelope, isAuthMfeMessage } from "./protocol"

describe("protocol", () => {
  it("round-trips every message type", () => {
    const messages = [
      envelope({ type: "auth:ready", nonce: "n" }),
      envelope({ type: "auth:success", nonce: "n", code: "c" }),
      envelope({ type: "auth:error", nonce: "n", reason: "unavailable" }),
      envelope({ type: "auth:cancel", nonce: "n" }),
      envelope({ type: "auth:resize", nonce: "n", height: 420 }),
    ]
    for (const message of messages) expect(isAuthMfeMessage(message)).toBe(true)
  })

  it.each([
    null,
    "auth:success",
    { type: "auth:success", nonce: "n", code: "c" },
    { ...envelope({ type: "auth:cancel", nonce: "n" }), v: 2 },
    { ...envelope({ type: "auth:cancel", nonce: "n" }), source: "other" },
    { ...envelope({ type: "auth:cancel", nonce: "n" }), type: "auth:unknown" },
    { ...envelope({ type: "auth:success", nonce: "n", code: "c" }), code: "" },
    { ...envelope({ type: "auth:resize", nonce: "n", height: 1 }), height: Number.NaN },
    { ...envelope({ type: "auth:ready", nonce: "n" }), nonce: 1 },
  ])("rejects %j", (value) => {
    expect(isAuthMfeMessage(value)).toBe(false)
  })
})
