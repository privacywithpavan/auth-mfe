/**
 * postMessage protocol between the auth MFE iframe and the chatbot page.
 * Shared by both sides; bump PROTOCOL_VERSION on breaking changes.
 */
export const PROTOCOL_VERSION = 1
export const MESSAGE_SOURCE = "auth-mfe"

export type AuthErrorReason = "unavailable" | "invalid_embed"

export type AuthMfeMessage =
  /** The iframe has loaded and is ready for input. */
  | { type: "auth:ready"; nonce: string }
  /** Login or registration succeeded; the chatbot backend redeems `code`. */
  | { type: "auth:success"; nonce: string; code: string }
  /** The flow can't continue in the iframe. */
  | { type: "auth:error"; nonce: string; reason: AuthErrorReason }
  /** The user closed the dialog. */
  | { type: "auth:cancel"; nonce: string }
  /** Content height changed; the chatbot can resize the iframe. */
  | { type: "auth:resize"; nonce: string; height: number }

export type AuthMfeEnvelope = AuthMfeMessage & { v: typeof PROTOCOL_VERSION; source: typeof MESSAGE_SOURCE }

export function envelope(message: AuthMfeMessage): AuthMfeEnvelope {
  return { ...message, v: PROTOCOL_VERSION, source: MESSAGE_SOURCE }
}

const TYPES = new Set(["auth:ready", "auth:success", "auth:error", "auth:cancel", "auth:resize"])

/** Shape check for received messages. Callers must still check event.origin, event.source and nonce. */
export function isAuthMfeMessage(data: unknown): data is AuthMfeEnvelope {
  if (typeof data !== "object" || data === null) return false
  const message = data as Record<string, unknown>
  if (message.v !== PROTOCOL_VERSION || message.source !== MESSAGE_SOURCE) return false
  if (typeof message.type !== "string" || !TYPES.has(message.type) || typeof message.nonce !== "string") {
    return false
  }
  switch (message.type) {
    case "auth:success":
      return typeof message.code === "string" && message.code.length > 0
    case "auth:error":
      return typeof message.reason === "string"
    case "auth:resize":
      return typeof message.height === "number" && Number.isFinite(message.height)
    default:
      return true
  }
}
