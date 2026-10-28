"use client"

import { useActionState } from "react"
import Link from "next/link"

import { initialAuthFormState } from "@/lib/auth-schemas"

import { loginAction } from "../actions"
import { useEmbed } from "../embed-context"
import { CancelButton, FormMessage, SubmitButton, SuccessHandoff, TextField } from "../form-parts"

export function LoginForm() {
  const { parentOrigin, query } = useEmbed()
  const [state, formAction, pending] = useActionState(loginAction, initialAuthFormState)

  if (state.status === "success") return <SuccessHandoff state={state} />

  const values = state.status === "error" ? state.values : undefined

  return (
    <form action={formAction} className="grid gap-4" noValidate>
      <input type="hidden" name="parent" value={parentOrigin} />
      <FormMessage state={state} />
      <TextField
        name="email"
        label="Email"
        type="email"
        autoComplete="username"
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
