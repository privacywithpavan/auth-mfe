"use client"

import { useActionState } from "react"
import Link from "next/link"

import { initialAuthFormState } from "@/lib/auth-schemas"

import { registerAction } from "../actions"
import { useEmbed } from "../embed-context"
import { CancelButton, FormMessage, SubmitButton, SuccessNotice, TextField } from "../form-parts"

export function RegisterForm() {
  const { parentOrigin, query } = useEmbed()
  const [state, formAction, pending] = useActionState(registerAction, initialAuthFormState)

  if (state.status === "success") return <SuccessNotice state={state} />

  const values = state.status === "error" ? state.values : undefined

  return (
    <form action={formAction} className="grid gap-4" noValidate>
      <input type="hidden" name="parent" value={parentOrigin} />
      <FormMessage state={state} />
      <TextField name="name" label="Name" autoComplete="name" required defaultValue={values?.name} state={state} />
      <TextField
        name="email"
        label="Email"
        type="email"
        autoComplete="email"
        required
        defaultValue={values?.email}
        state={state}
      />
      <TextField
        name="password"
        label="Password"
        type="password"
        autoComplete="new-password"
        minLength={8}
        required
        state={state}
      />
      <TextField
        name="confirmPassword"
        label="Confirm password"
        type="password"
        autoComplete="new-password"
        required
        state={state}
      />
      <div className="grid gap-2">
        <SubmitButton pending={pending}>Create account</SubmitButton>
        <CancelButton />
      </div>
      <p className="text-center text-sm text-muted-foreground">
        Already have an account?{" "}
        <Link href={`/login?${query}`} className="font-medium text-foreground underline-offset-4 hover:underline">
          Sign in
        </Link>
      </p>
    </form>
  )
}
