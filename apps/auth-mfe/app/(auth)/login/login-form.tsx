"use client"

import { startTransition, useActionState, useCallback } from "react"
import Link from "next/link"

import { initialAuthFormState } from "@/lib/auth-schemas"

import { loginAction } from "../actions"
import { useEmbed } from "../embed-context"
import { CancelButton, FormMessage, SubmitButton, SuccessNotice, TextField } from "../form-parts"
import { EnrollPasskey, PasskeySignIn, SecondFactor, type SubmitStep } from "./passkey-steps"

export function LoginForm() {
  const { parentOrigin, query } = useEmbed()
  const [state, formAction, pending] = useActionState(loginAction, initialAuthFormState)

  const submit = useCallback<SubmitStep>(
    (fields) => {
      const formData = new FormData()
      formData.set("parent", parentOrigin)
      for (const [name, value] of Object.entries(fields)) formData.set(name, value)
      startTransition(() => formAction(formData))
    },
    [parentOrigin, formAction]
  )

  switch (state.status) {
    case "success":
      return <SuccessNotice state={state} />
    case "second_factor":
      return <SecondFactor state={state} formAction={formAction} submit={submit} pending={pending} />
    case "enroll":
      return <EnrollPasskey state={state} submit={submit} pending={pending} />
  }

  const values = state.status === "error" ? state.values : undefined

  return (
    <form action={formAction} className="grid gap-4" noValidate>
      <input type="hidden" name="parent" value={parentOrigin} />
      <FormMessage state={state} />
      <TextField
        name="email"
        label="Email"
        type="email"
        // "webauthn" lets the browser offer saved passkeys here too, next to saved passwords.
        autoComplete="username webauthn"
        required
        defaultValue={values?.email}
        state={state}
      />
      <TextField
        name="password"
        label="Password"
        type="password"
        autoComplete="current-password"
        required
        state={state}
      />
      <div className="grid gap-2">
        <SubmitButton pending={pending}>Sign in</SubmitButton>
        <PasskeySignIn submit={submit} pending={pending} refreshKey={state} />
        <CancelButton />
      </div>
      <p className="text-center text-sm text-muted-foreground">
        New here?{" "}
        <Link href={`/register?${query}`} className="font-medium text-foreground underline-offset-4 hover:underline">
          Create an account
        </Link>
      </p>
    </form>
  )
}
