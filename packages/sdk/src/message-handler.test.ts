import { describe, expect, it } from "vitest"

import { createMessageHandler, MAX_HEIGHT, MIN_HEIGHT } from "./message-handler"
import { envelope, type AuthMfeMessage } from "./protocol"

const AUTH = "https://auth.localtest.me:3000"
const NONCE = "nonce-abcdefghijklmnop"
const iframeWindow = {}

const handle = createMessageHandler({ authOrigin: AUTH, nonce: NONCE, getIframeWindow: () => iframeWindow })

function event(message: AuthMfeMessage | unknown, overrides: { origin?: string; source?: unknown } = {}) {
  return {
    origin: overrides.origin ?? AUTH,
    source: (overrides.source ?? iframeWindow) as MessageEventSource,
    data: message,
  }
}

describe("createMessageHandler", () => {
  it("accepts success from our iframe with our nonce", () => {
    expect(handle(event(envelope({ type: "auth:success", nonce: NONCE })))).toEqual({ kind: "success" })
  })

  it.each([
    ["another origin", { origin: "https://evil.example" }],
    ["a look-alike origin", { origin: "https://auth.localtest.me:3000.evil.example" }],
    ["another window on the right origin", { source: {} }],
  ])("ignores messages from %s", (_label, overrides) => {
    expect(handle(event(envelope({ type: "auth:success", nonce: NONCE }), overrides))).toEqual({
      kind: "ignore",
    })
  })

  it("ignores a stale nonce and malformed data", () => {
    expect(handle(event(envelope({ type: "auth:success", nonce: "old-attempt-nonce" })))).toEqual({
      kind: "ignore",
    })
    expect(handle(event({ type: "auth:success", nonce: NONCE }))).toEqual({ kind: "ignore" })
    expect(handle(event("auth:success"))).toEqual({ kind: "ignore" })
  })

  it("ignores everything once the iframe is gone", () => {
    const detached = createMessageHandler({ authOrigin: AUTH, nonce: NONCE, getIframeWindow: () => null })
    expect(detached({ origin: AUTH, source: null, data: envelope({ type: "auth:cancel", nonce: NONCE }) })).toEqual({
      kind: "ignore",
    })
  })

  it("clamps resize heights", () => {
    expect(handle(event(envelope({ type: "auth:resize", nonce: NONCE, height: 10 })))).toEqual({
      kind: "resize",
      height: MIN_HEIGHT,
    })
    expect(handle(event(envelope({ type: "auth:resize", nonce: NONCE, height: 1e9 })))).toEqual({
      kind: "resize",
      height: MAX_HEIGHT,
    })
    expect(handle(event(envelope({ type: "auth:resize", nonce: NONCE, height: 512.4 })))).toEqual({
      kind: "resize",
      height: 513,
    })
  })

  it("maps ready, cancel and error", () => {
    expect(handle(event(envelope({ type: "auth:ready", nonce: NONCE })))).toEqual({ kind: "ready" })
    expect(handle(event(envelope({ type: "auth:cancel", nonce: NONCE })))).toEqual({ kind: "cancel" })
    expect(handle(event(envelope({ type: "auth:error", nonce: NONCE, reason: "unavailable" })))).toEqual({
      kind: "error",
      reason: "unavailable",
    })
  })
})
