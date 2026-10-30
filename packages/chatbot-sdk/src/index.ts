/**
 * Chatbot-side SDK for embedding the auth MFE. The chatbot and the MFE must share an org
 * root domain: on success the MFE sets an HttpOnly `auth_token` cookie on that domain
 * (a short-lived JWT signed by the IdP), which YOUR backend verifies against the IdP's JWKS.
 *
 *   const result = await openAuthMfe({ authOrigin: "https://auth.example.com", container })
 *   if (result.status === "success") {
 *     // The cookie is set; ask your backend who the user is.
 *   }
 *
 * The JWT lives a few minutes. When your backend rejects it as expired, call
 * refreshAuthSession() and retry; logoutAuthSession() ends the session everywhere.
 */
import { createMessageHandler } from "./message-handler"

export { isAuthMfeMessage, PROTOCOL_VERSION, type AuthErrorReason, type AuthMfeMessage } from "./protocol"

export type AuthMfePage = "login" | "register"

export type OpenAuthMfeOptions = {
  /** Origin of the auth MFE, e.g. https://auth.example.com (no path or trailing slash). */
  authOrigin: string
  /** Element the iframe is appended to. The caller owns showing/hiding it (e.g. a dialog). */
  container: HTMLElement
  /** Which form to open on. Users can switch between them inside the iframe. */
  page?: AuthMfePage
  /** Abort to close the iframe from the chatbot side (rejects with the signal's reason). */
  signal?: AbortSignal
  /** Fail if the iframe hasn't said it's ready by then, e.g. because framing was refused. */
  readyTimeoutMs?: number
  /** Accessible name of the iframe. */
  title?: string
}

export type AuthMfeResult = { status: "success" } | { status: "cancelled" }

export class AuthMfeError extends Error {
  constructor(readonly reason: "timeout" | "unavailable" | "invalid_embed") {
    super(`Auth MFE failed: ${reason}`)
    this.name = "AuthMfeError"
  }
}

function createNonce() {
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

/** Embeds the login iframe and resolves when the user signs in or cancels. */
export function openAuthMfe({
  authOrigin,
  container,
  page = "login",
  signal,
  readyTimeoutMs = 15_000,
  title = "Sign in",
}: OpenAuthMfeOptions): Promise<AuthMfeResult> {
  if (new URL(authOrigin).origin !== authOrigin) {
    throw new TypeError(`authOrigin must be a bare origin, got "${authOrigin}"`)
  }
  signal?.throwIfAborted()

  const nonce = createNonce()
  const url = new URL(`/${page}`, authOrigin)
  url.searchParams.set("parent", window.location.origin)
  url.searchParams.set("nonce", nonce)

  const iframe = document.createElement("iframe")
  iframe.src = url.href
  iframe.title = title
  // Forms + scripts + its own cookies; no top navigation, popups or downloads.
  iframe.setAttribute("sandbox", "allow-forms allow-scripts allow-same-origin")
  // Lets the MFE use passkeys (WebAuthn) inside the iframe. Without it, browsers block them there.
  iframe.allow = "publickey-credentials-get; publickey-credentials-create"
  iframe.referrerPolicy = "origin"
  iframe.style.cssText = "display:block;width:100%;height:420px;border:0;color-scheme:normal"

  return new Promise<AuthMfeResult>((resolve, reject) => {
    const handle = createMessageHandler({ authOrigin, nonce, getIframeWindow: () => iframe.contentWindow })

    const readyTimer = setTimeout(() => finish(() => reject(new AuthMfeError("timeout"))), readyTimeoutMs)

    function onMessage(event: MessageEvent) {
      const action = handle(event)
      switch (action.kind) {
        case "ready":
          clearTimeout(readyTimer)
          break
        case "resize":
          iframe.style.height = `${action.height}px`
          break
        case "success":
          finish(() => resolve({ status: "success" }))
          break
        case "cancel":
          finish(() => resolve({ status: "cancelled" }))
          break
        case "error":
          finish(() => reject(new AuthMfeError(action.reason)))
          break
      }
    }

    function onAbort() {
      finish(() => reject(signal?.reason))
    }

    function finish(settle: () => void) {
      clearTimeout(readyTimer)
      window.removeEventListener("message", onMessage)
      signal?.removeEventListener("abort", onAbort)
      iframe.remove()
      settle()
    }

    window.addEventListener("message", onMessage)
    signal?.addEventListener("abort", onAbort, { once: true })
    container.append(iframe)
  })
}

/**
 * Asks the MFE's BFF to re-issue the auth_token cookie from its session. Resolves to false
 * when there's no session left (the user has to sign in again).
 */
export async function refreshAuthSession({ authOrigin }: { authOrigin: string }): Promise<boolean> {
  const response = await fetch(new URL("/api/session/refresh", authOrigin), { method: "POST", credentials: "include" })
  if (response.ok) return true
  if (response.status === 401) return false
  throw new AuthMfeError("unavailable")
}

/** Ends the session at the MFE's BFF and the IdP, and clears its cookies. */
export async function logoutAuthSession({ authOrigin }: { authOrigin: string }): Promise<void> {
  const response = await fetch(new URL("/api/session/logout", authOrigin), { method: "POST", credentials: "include" })
  if (!response.ok) throw new AuthMfeError("unavailable")
}
