"use client"

import { useEffect, type ComponentProps } from "react"
import { CircleAlertIcon, CircleCheckIcon } from "lucide-react"

import { Alert, AlertDescription } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Spinner } from "@/components/ui/spinner"
import type { AuthFormState, FormField } from "@/lib/auth-schemas"

import { useEmbed } from "./embed-context"

export function TextField({
  name,
  label,
  state,
  ...props
}: { name: FormField; label: string; state: AuthFormState } & Omit<ComponentProps<"input">, "name">) {
  const error = "fieldErrors" in state ? state.fieldErrors?.[name] : undefined
  const errorId = `${name}-error`
  return (
    <div className="grid gap-1.5">
      <Label htmlFor={name}>{label}</Label>
      <Input
        id={name}
        name={name}
        aria-invalid={error ? true : undefined}
        aria-describedby={error ? errorId : undefined}
        {...props}
      />
      {error && (
        <p id={errorId} className="text-sm text-destructive">
          {error}
        </p>
      )}
    </div>
  )
}

export function FormMessage({ state }: { state: AuthFormState }) {
  return <ErrorMessage message={"message" in state ? state.message : undefined} />
}

export function ErrorMessage({ message }: { message?: string }) {
  if (!message) return null
  return (
    <Alert variant="destructive" aria-live="polite">
      <CircleAlertIcon />
      <AlertDescription>{message}</AlertDescription>
    </Alert>
  )
}

export function SubmitButton({
  pending,
  children,
  ...props
}: { pending: boolean; children: string } & Omit<ComponentProps<typeof Button>, "children">) {
  return (
    <Button type="submit" size="lg" className="w-full" disabled={pending} {...props}>
      {pending && <Spinner data-icon="inline-start" />}
      {children}
    </Button>
  )
}

export function CancelButton() {
  const { post } = useEmbed()
  return (
    <Button type="button" variant="ghost" size="lg" className="w-full" onClick={() => post({ type: "auth:cancel" })}>
      Cancel
    </Button>
  )
}

/** Tells the chatbot once that the auth_token cookie is set, then shows a short confirmation. */
export function SuccessNotice({ state }: { state: Extract<AuthFormState, { status: "success" }> }) {
  const { post } = useEmbed()
  useEffect(() => {
    post({ type: "auth:success" })
  }, [post])

  return (
    <Alert aria-live="polite">
      <CircleCheckIcon />
      <AlertDescription>
        Signed in as {state.user.name}. Returning to the chat…
      </AlertDescription>
    </Alert>
  )
}
