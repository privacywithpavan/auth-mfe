import { z } from "zod"

import { loginSchema, registerSchema, type AuthFormState, type FormField } from "./auth-schemas"
import { mintHandoffCode } from "./handoff"
import type { IdpClient, IdpError, IdpTokens, IdpUser } from "./idp/types"
import { parseAllowedParentOrigin } from "./origins"
import { hitRateLimit, RATE_LIMITS, resetRateLimit, type RateLimitResult } from "./rate-limit"
import type { KeyValueStore } from "./store"

/**
 * The login/register Server Actions, minus Next.js plumbing so they can be tested.
 * Order matters: validate → rate limit → IdP → session → handoff code.
 */
export type AuthFlowDeps = {
  store: KeyValueStore
  idp: IdpClient
  allowedParentOrigins: readonly string[]
  handoffTtlSeconds: number
  /** Creates the BFF session and sets its cookie; returns the session's store key. */
  startSession: (user: IdpUser, tokens: IdpTokens) => Promise<{ key: string }>
}

export type AuthRequest = {
  formData: FormData
  /** Client IP for rate limiting. */
  ip: string
}

const MESSAGES: Record<IdpError, string> = {
  invalid_credentials: "Email or password is incorrect.",
  locked: "This account is temporarily locked. Try again later.",
  email_taken: "An account with this email already exists. Try signing in instead.",
  weak_password: "Choose a stronger password.",
  invalid_request: "Check your details and try again.",
  invalid_grant: "Your session has expired. Please sign in again.",
  unavailable: "Sign-in is temporarily unavailable. Please try again in a moment.",
}

const INVALID_EMBED = "This page must be opened from the chatbot. Close it and try again."

function field(formData: FormData, name: string) {
  const value = formData.get(name)
  return typeof value === "string" ? value : ""
}

function tooManyAttempts(result: Extract<RateLimitResult, { allowed: false }>, values: { email?: string; name?: string }): AuthFormState {
  const minutes = Math.ceil(result.retryAfterSeconds / 60)
  return {
    status: "error",
    message: `Too many attempts. Try again in ${minutes} minute${minutes === 1 ? "" : "s"}.`,
    values,
  }
}

function fieldErrors(error: z.ZodError): Partial<Record<FormField, string>> {
  const errors: Partial<Record<FormField, string>> = {}
  for (const issue of error.issues) {
    const name = issue.path[0] as FormField
    errors[name] ??= issue.message
  }
  return errors
}

async function complete(
  deps: AuthFlowDeps,
  parentOrigin: string,
  user: IdpUser,
  tokens: IdpTokens
): Promise<AuthFormState> {
  const { key } = await deps.startSession(user, tokens)
  const code = await mintHandoffCode(deps.store, {
    sessionKey: key,
    user,
    parentOrigin,
    ttlSeconds: deps.handoffTtlSeconds,
  })
  return { status: "success", code, user: { name: user.name, email: user.email } }
}

export async function runLogin(deps: AuthFlowDeps, { formData, ip }: AuthRequest): Promise<AuthFormState> {
  const parentOrigin = parseAllowedParentOrigin(field(formData, "parent"), deps.allowedParentOrigins)
  if (!parentOrigin) return { status: "error", message: INVALID_EMBED }

  const parsed = loginSchema.safeParse({ email: field(formData, "email"), password: field(formData, "password") })
  const values = { email: field(formData, "email") }
  if (!parsed.success) return { status: "error", fieldErrors: fieldErrors(parsed.error), values }
  const { email, password } = parsed.data

  for (const [rule, subject] of [
    [RATE_LIMITS.loginPerIp, ip],
    [RATE_LIMITS.loginPerEmail, email],
  ] as const) {
    const limit = await hitRateLimit(deps.store, rule, subject)
    if (!limit.allowed) return tooManyAttempts(limit, values)
  }

  const result = await deps.idp.login({ email, password })
  if (!result.ok) return { status: "error", message: MESSAGES[result.error], values }

  await resetRateLimit(deps.store, RATE_LIMITS.loginPerEmail, email)
  return complete(deps, parentOrigin, result.user, result.tokens)
}

export async function runRegister(deps: AuthFlowDeps, { formData, ip }: AuthRequest): Promise<AuthFormState> {
  const parentOrigin = parseAllowedParentOrigin(field(formData, "parent"), deps.allowedParentOrigins)
  if (!parentOrigin) return { status: "error", message: INVALID_EMBED }

  const values = { email: field(formData, "email"), name: field(formData, "name") }
  const parsed = registerSchema.safeParse({
    name: field(formData, "name"),
    email: field(formData, "email"),
    password: field(formData, "password"),
    confirmPassword: field(formData, "confirmPassword"),
  })
  if (!parsed.success) return { status: "error", fieldErrors: fieldErrors(parsed.error), values }
  const { name, email, password } = parsed.data

  const limit = await hitRateLimit(deps.store, RATE_LIMITS.registerPerIp, ip)
  if (!limit.allowed) return tooManyAttempts(limit, values)

  const result = await deps.idp.register({ name, email, password })
  if (!result.ok) {
    if (result.error === "weak_password") {
      return { status: "error", fieldErrors: { password: MESSAGES.weak_password }, values }
    }
    return { status: "error", message: MESSAGES[result.error], values }
  }
  return complete(deps, parentOrigin, result.user, result.tokens)
}
