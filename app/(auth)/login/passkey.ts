import {
  startAuthentication,
  startRegistration,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
} from "@simplewebauthn/browser"

import type { PasskeyOptions } from "@/lib/idp/types"

/**
 * Browser side of the passkey ceremonies. Call these first thing in a click handler:
 * browsers only allow WebAuthn right after a user gesture, so the options must
 * already be on the page. The exception is autofill (conditional mediation), which
 * waits in the background until the user picks a passkey from the username field.
 */
export type PasskeyOutcome = { ok: true; response: string } | { ok: false; message: string }

function failure(error: unknown, creating: boolean): PasskeyOutcome {
  switch ((error as Error | undefined)?.name) {
    case "NotAllowedError":
      return { ok: false, message: creating ? "Passkey creation was cancelled or timed out." : "Passkey sign-in was cancelled or timed out." }
    case "InvalidStateError":
      return { ok: false, message: "This device already has a passkey for your account." }
    case "AbortError":
      // We cancelled it: another ceremony started (e.g. the button replaced autofill) or the step changed.
      return { ok: false, message: "Passkey request was cancelled." }
    case "SecurityError":
    case "NotSupportedError":
      return { ok: false, message: "Passkeys aren't available in this window." }
    default:
      console.error("[passkey]", error)
      return { ok: false, message: "Something went wrong with the passkey. Please try again." }
  }
}

export async function getPasskey(options: PasskeyOptions, { autofill = false } = {}): Promise<PasskeyOutcome> {
  try {
    const response = await startAuthentication({
      optionsJSON: options as unknown as PublicKeyCredentialRequestOptionsJSON,
      useBrowserAutofill: autofill,
    })
    return { ok: true, response: JSON.stringify(response) }
  } catch (error) {
    return failure(error, false)
  }
}

export async function createPasskey(options: PasskeyOptions): Promise<PasskeyOutcome> {
  try {
    const response = await startRegistration({ optionsJSON: options as unknown as PublicKeyCredentialCreationOptionsJSON })
    return { ok: true, response: JSON.stringify(response) }
  } catch (error) {
    return failure(error, true)
  }
}
