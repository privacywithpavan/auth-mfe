"use client"

import { useEffect, useState } from "react"
import { browserSupportsWebAuthn, browserSupportsWebAuthnAutofill, WebAuthnAbortService } from "@simplewebauthn/browser"
import { KeyRoundIcon } from "lucide-react"

import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"
import type { PasskeyChallenge } from "@/lib/auth-flow"
import type { AuthFormState } from "@/lib/auth-schemas"

import { passkeyChallengeAction } from "../actions"
import { useEmbed } from "../embed-context"
import { CancelButton, ErrorMessage, FormMessage, SubmitButton, TextField } from "../form-parts"
import { createPasskey, getPasskey, type PasskeyOutcome } from "./passkey"

/** Runs a login step outside a <form>, e.g. with the browser's passkey response. */
export type SubmitStep = (fields: Record<string, string>) => void

/** Runs a browser passkey ceremony from a click, then submits its response or shows why it failed. */
function usePasskeyCeremony(submit: SubmitStep) {
  const [message, setMessage] = useState<string>()
  const [busy, setBusy] = useState(false)

  async function run(ceremony: () => Promise<PasskeyOutcome>, fields: Record<string, string>) {
    setMessage(undefined)
    setBusy(true)
    const outcome = await ceremony()
    setBusy(false)
    if (outcome.ok) submit({ ...fields, response: outcome.response })
    else setMessage(outcome.message)
  }

  return { message, busy, run }
}

function PasskeyButton({
  busy,
  disabled,
  variant,
  onClick,
  children,
}: {
  busy: boolean
  disabled: boolean
  variant?: "outline"
  onClick: () => void
  children: string
}) {
  return (
    <Button type="button" size="lg" variant={variant} className="w-full" disabled={disabled || busy} onClick={onClick}>
      {busy ? <Spinner data-icon="inline-start" /> : <KeyRoundIcon data-icon="inline-start" />}
      {children}
    </Button>
  )
}

/**
 * Passkey-first sign-in on the password form. Fetches its challenge on load and after
 * every server response (`refreshKey`), since a failed attempt burns the challenge.
 *
 * The same challenge also feeds passkey autofill: where the browser supports it, saved
 * passkeys show up in the email field's suggestions next to saved passwords. The
 * button stays for browsers (and iframes) without autofill support.
 */
export function PasskeySignIn({ submit, pending, refreshKey }: { submit: SubmitStep; pending: boolean; refreshKey: unknown }) {
  const { parentOrigin } = useEmbed()
  // undefined while loading, null when passkeys can't be offered here.
  const [challenge, setChallenge] = useState<PasskeyChallenge | null>()
  const { message, busy, run } = usePasskeyCeremony(submit)

  useEffect(() => {
    let active = true
    const next = browserSupportsWebAuthn() ? passkeyChallengeAction(parentOrigin) : Promise.resolve(null)
    next.then(
      (value) => active && setChallenge(value),
      () => active && setChallenge(null)
    )
    return () => {
      active = false
    }
  }, [parentOrigin, refreshKey])

  useEffect(() => {
    if (!challenge) return
    let active = true
    browserSupportsWebAuthnAutofill().then(async (supported) => {
      if (!supported || !active) return
      const outcome = await getPasskey(challenge.options, { autofill: true })
      // Failures stay quiet: this also ends when the button starts its own ceremony or the step changes.
      if (outcome.ok && active) submit({ intent: "passkey", ticket: challenge.ticket, response: outcome.response })
    })
    return () => {
      active = false
      WebAuthnAbortService.cancelCeremony()
    }
  }, [challenge, submit])

  if (challenge === null) return null
  return (
    <>
      <ErrorMessage message={message} />
      <PasskeyButton
        variant="outline"
        busy={busy}
        disabled={!challenge || pending}
        onClick={() => challenge && run(() => getPasskey(challenge.options), { intent: "passkey", ticket: challenge.ticket })}
      >
        Sign in with a passkey
      </PasskeyButton>
    </>
  )
}

/** The password login's second factor: the user's passkey, or an emailed code. */
export function SecondFactor({
  state,
  formAction,
  submit,
  pending,
}: {
  state: Extract<AuthFormState, { status: "second_factor" }>
  formAction: (formData: FormData) => void
  submit: SubmitStep
  pending: boolean
}) {
  const { parentOrigin } = useEmbed()
  const { message, busy, run } = usePasskeyCeremony(submit)
  const { ticket, passkeyOptions } = state

  if (state.method === "passkey" && passkeyOptions) {
    return (
      <div className="grid gap-4">
        <p className="text-sm text-muted-foreground">Confirm it&apos;s you with your passkey.</p>
        <ErrorMessage message={message ?? state.message} />
        <div className="grid gap-2">
          <PasskeyButton
            busy={busy}
            disabled={pending}
            onClick={() => run(() => getPasskey(passkeyOptions), { intent: "passkey", ticket })}
          >
            Use passkey
          </PasskeyButton>
          <Button
            type="button"
            variant="ghost"
            size="lg"
            className="w-full"
            disabled={pending || busy}
            onClick={() => submit({ intent: "send_otp", ticket })}
          >
            Email me a code instead
          </Button>
          <CancelButton />
        </div>
      </div>
    )
  }

  return (
    <form action={formAction} className="grid gap-4" noValidate>
      <input type="hidden" name="parent" value={parentOrigin} />
      <input type="hidden" name="ticket" value={ticket} />
      <p className="text-sm text-muted-foreground">We emailed you a 6-digit code. Enter it to continue.</p>
      <FormMessage state={state} />
      <TextField
        name="code"
        label="Code"
        inputMode="numeric"
        autoComplete="one-time-code"
        maxLength={6}
        required
        autoFocus
        state={state}
      />
      <div className="grid gap-2">
        {/* The first submit button is the one Enter presses. */}
        <SubmitButton pending={pending} name="intent" value="verify_otp">
          Verify
        </SubmitButton>
        <Button type="submit" name="intent" value="send_otp" variant="ghost" size="lg" className="w-full" disabled={pending}>
          Send a new code
        </Button>
        <CancelButton />
      </div>
    </form>
  )
}

/** After an emailed-code login: offer a passkey for this device, or continue without one. */
export function EnrollPasskey({
  state,
  submit,
  pending,
}: {
  state: Extract<AuthFormState, { status: "enroll" }>
  submit: SubmitStep
  pending: boolean
}) {
  const { message, busy, run } = usePasskeyCeremony(submit)
  const { ticket, options } = state

  return (
    <div className="grid gap-4">
      <p className="text-sm text-muted-foreground">
        You&apos;re verified. Create a passkey to sign in next time with your fingerprint, face or screen lock.
      </p>
      <ErrorMessage message={message ?? state.message} />
      <div className="grid gap-2">
        <PasskeyButton busy={busy} disabled={pending} onClick={() => run(() => createPasskey(options), { intent: "enroll", ticket })}>
          Create a passkey
        </PasskeyButton>
        <Button
          type="button"
          variant="ghost"
          size="lg"
          className="w-full"
          disabled={pending || busy}
          onClick={() => submit({ intent: "skip_enroll", ticket })}
        >
          Not now
        </Button>
      </div>
    </div>
  )
}
