import { isAuthMfeMessage, type AuthErrorReason } from "./protocol"

export type HandlerAction =
  | { kind: "ignore" }
  | { kind: "ready" }
  | { kind: "resize"; height: number }
  | { kind: "success" }
  | { kind: "cancel" }
  | { kind: "error"; reason: AuthErrorReason }

/** Bounds for iframe height, so a bad message can't blow up the chatbot layout. */
export const MIN_HEIGHT = 160
export const MAX_HEIGHT = 1200

/**
 * Decides what an incoming `message` event means. Pure, so it's testable without a DOM.
 * A message counts only if it comes from the auth origin, from our own iframe,
 * and echoes the nonce we generated for this attempt.
 */
export function createMessageHandler({
  authOrigin,
  nonce,
  getIframeWindow,
}: {
  authOrigin: string
  nonce: string
  getIframeWindow: () => unknown
}) {
  return (event: Pick<MessageEvent, "origin" | "source" | "data">): HandlerAction => {
    if (event.origin !== authOrigin) return { kind: "ignore" }
    const iframeWindow = getIframeWindow()
    if (!iframeWindow || event.source !== iframeWindow) return { kind: "ignore" }
    if (!isAuthMfeMessage(event.data) || event.data.nonce !== nonce) return { kind: "ignore" }

    const message = event.data
    switch (message.type) {
      case "auth:ready":
        return { kind: "ready" }
      case "auth:resize":
        return { kind: "resize", height: Math.min(MAX_HEIGHT, Math.max(MIN_HEIGHT, Math.ceil(message.height))) }
      case "auth:success":
        return { kind: "success" }
      case "auth:cancel":
        return { kind: "cancel" }
      case "auth:error":
        return { kind: "error", reason: message.reason }
      default:
        return { kind: "ignore" }
    }
  }
}
