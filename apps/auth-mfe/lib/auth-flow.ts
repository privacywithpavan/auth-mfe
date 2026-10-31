import { z } from "zod"

import { loginSchema, otpSchema, registerSchema, type AuthFormState, type FormField } from "./auth-schemas"
import type { IdpClient, IdpError, IdpTokens, IdpUser, PasskeyOptions, PasskeyResponse } from "./idp/types"
import { consumeMfaTicket, mintMfaTicket, readMfaTicket, updateMfaTicket, type MfaTicket } from "./mfa-ticket"
import { parseAllowedParentOrigin } from "./origins"
import { hitRateLimit, RATE_LIMITS, resetRateLimit, type RateLimitResult } from "./rate-limit"
import type { KeyValueStore } from "./store"

/**
 * The login/register Server Actions, minus Next.js plumbing so they can be tested.
 * Order matters: validate → rate limit → IdP → (second factor) → session (sets the cookies).
 */
export type AuthFlowDeps = {
  store: KeyValueStore
  idp: IdpClient
  allowedParentOrigins: readonly string[]
  /** Creates the BFF session and sets its cookies (including the domain-wide auth_token). */
  startSession: (user: IdpUser, tokens: IdpTokens) => Promise<void>
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
  invalid_code: "That code is incorrect or has expired.",
  passkey_failed: "That passkey couldn't be verified. Try again or use another way to sign in.",
  unavailable: "Sign-in is temporarily unavailable. Please try again in a moment.",
}

const INVALID_EMBED = "This page must be opened from the chatbot. Close it and try again."

function field(formData: FormData, name: string) {
  const value = formData.get(name)
  return typeof value === "string" ? value : ""
}

function tooManyMessage(result: Extract<RateLimitResult, { allowed: false }>) {
  const minutes = Math.ceil(result.retryAfterSeconds / 60)
  return `Too many attempts. Try again in ${minutes} minute${minutes === 1 ? "" : "s"}.`
}

function tooManyAttempts(result: Extract<RateLimitResult, { allowed: false }>, values?: { email?: string; name?: string }): AuthFormState {
  return { status: "error", message: tooManyMessage(result), values }
}

/** Ends the multi-step flow; the form starts over at the password. */
function failed(error: IdpError): AuthFormState {
  return { status: "error", message: MESSAGES[error] }
}

function fieldErrors(error: z.ZodError, onField?: FormField): Partial<Record<FormField, string>> {
  const errors: Partial<Record<FormField, string>> = {}
  for (const issue of error.issues) {
    const name = onField ?? (issue.path[0] as FormField)
    errors[name] ??= issue.message
  }
  return errors
}

async function complete(deps: AuthFlowDeps, user: IdpUser, tokens: IdpTokens): Promise<AuthFormState> {
  await deps.startSession(user, tokens)
  return { status: "success", user: { name: user.name, email: user.email } }
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
  if (result.ok === "mfa_required") {
    await resetRateLimit(deps.store, RATE_LIMITS.loginPerEmail, email)
    const ticket: MfaTicket = {
      kind: "password",
      idpTransaction: result.transaction,
      parentOrigin,
      email,
      hasPasskey: result.hasPasskey,
    }
    return secondFactorPrompt(deps, await mintMfaTicket(deps.store, ticket), ticket)
  }
  if (!result.ok) return { status: "error", message: MESSAGES[result.error], values }

  await resetRateLimit(deps.store, RATE_LIMITS.loginPerEmail, email)
  return complete(deps, result.user, result.tokens)
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
  return complete(deps, result.user, result.tokens)
}

// --- Second factor and passkeys --------------------------------------------------

/**
 * Asks for the password login's second factor: the user's passkey if they have one,
 * else an emailed code. The code also gates creating a first passkey, so a stolen
 * password alone can't enroll one.
 */
async function secondFactorPrompt(
  deps: AuthFlowDeps,
  token: string,
  ticket: MfaTicket,
  message?: string
): Promise<AuthFormState> {
  if (ticket.hasPasskey) {
    const options = await deps.idp.passkeyAuthenticationOptions(ticket.idpTransaction)
    if (options.ok) {
      return { status: "second_factor", ticket: token, method: "passkey", passkeyOptions: options.options, message }
    }
    if (options.error === "invalid_grant") return failed("invalid_grant")
  }
  return sendOtp(deps, token, ticket)
}

async function sendOtp(deps: AuthFlowDeps, token: string, ticket: MfaTicket): Promise<AuthFormState> {
  if (ticket.kind !== "password" || !ticket.email || ticket.verified) return failed("invalid_request")
  const limit = await hitRateLimit(deps.store, RATE_LIMITS.otpSendPerEmail, ticket.email)
  if (!limit.allowed) return { status: "second_factor", ticket: token, method: "otp", message: tooManyMessage(limit) }
  const sent = await deps.idp.sendEmailOtp(ticket.idpTransaction)
  if (!sent.ok) return failed(sent.error)
  return { status: "second_factor", ticket: token, method: "otp" }
}

type Step = AuthRequest & { deps: AuthFlowDeps; token: string; ticket: MfaTicket; parentOrigin: string }

/** WebAuthn responses are a few KB; anything much bigger isn't one. */
const MAX_PASSKEY_RESPONSE_LENGTH = 32_000

function passkeyResponse(formData: FormData): PasskeyResponse | undefined {
  const raw = field(formData, "response")
  if (!raw || raw.length > MAX_PASSKEY_RESPONSE_LENGTH) return undefined
  try {
    const value: unknown = JSON.parse(raw)
    return typeof value === "object" && value !== null && !Array.isArray(value) ? (value as PasskeyResponse) : undefined
  } catch {
    return undefined
  }
}

/** Burns the ticket and hands off. Losing the race to a concurrent request counts as expired. */
async function finish(step: Step, user: IdpUser, tokens: IdpTokens): Promise<AuthFormState> {
  if (!(await consumeMfaTicket(step.deps.store, step.token, step.parentOrigin))) return failed("invalid_grant")
  return complete(step.deps, user, tokens)
}

async function finishVerified(step: Step): Promise<AuthFormState> {
  const ticket = await consumeMfaTicket(step.deps.store, step.token, step.parentOrigin)
  if (!ticket?.verified) return failed("invalid_grant")
  return complete(step.deps, ticket.verified.user, ticket.verified.tokens)
}

async function verifyOtp(step: Step): Promise<AuthFormState> {
  const { deps, token, ticket } = step
  if (ticket.kind !== "password" || !ticket.email || ticket.verified) return failed("invalid_request")
  const retry = (extra: { message?: string; fieldErrors?: Partial<Record<FormField, string>> }): AuthFormState => ({
    status: "second_factor",
    ticket: token,
    method: "otp",
    ...extra,
  })

  const code = otpSchema.safeParse(field(step.formData, "code"))
  if (!code.success) return retry({ fieldErrors: fieldErrors(code.error, "code") })
  const limit = await hitRateLimit(deps.store, RATE_LIMITS.mfaPerEmail, ticket.email)
  if (!limit.allowed) return retry({ message: tooManyMessage(limit) })

  const result = await deps.idp.verifyEmailOtp(ticket.idpTransaction, code.data)
  if (!result.ok) {
    if (result.error === "invalid_code") return retry({ fieldErrors: { code: MESSAGES.invalid_code } })
    await consumeMfaTicket(deps.store, token, step.parentOrigin)
    return failed(result.error)
  }
  await resetRateLimit(deps.store, RATE_LIMITS.mfaPerEmail, ticket.email)

  // Signed in. Offer a passkey for this device before handing off; never block sign-in on it.
  await updateMfaTicket(deps.store, token, { ...ticket, verified: { user: result.user, tokens: result.tokens } })
  const options = await deps.idp.passkeyRegistrationOptions(ticket.idpTransaction)
  if (!options.ok) return finishVerified(step)
  return { status: "enroll", ticket: token, options: options.options }
}

async function verifyPasskey(step: Step): Promise<AuthFormState> {
  const { deps, token, ticket } = step
  if (ticket.verified) return failed("invalid_request")
  const response = passkeyResponse(step.formData)
  if (!response) return failed("invalid_request")

  const limit = ticket.email
    ? await hitRateLimit(deps.store, RATE_LIMITS.mfaPerEmail, ticket.email)
    : await hitRateLimit(deps.store, RATE_LIMITS.passkeyPerIp, step.ip)
  if (!limit.allowed) return tooManyAttempts(limit)

  const result = await deps.idp.verifyPasskeyAuthentication(ticket.idpTransaction, response)
  if (!result.ok) {
    // A password login can retry with a fresh challenge, or fall back to the emailed code.
    if (result.error === "passkey_failed" && ticket.kind === "password") {
      return secondFactorPrompt(deps, token, ticket, MESSAGES.passkey_failed)
    }
    await consumeMfaTicket(deps.store, token, step.parentOrigin)
    return failed(result.error)
  }
  if (ticket.email) await resetRateLimit(deps.store, RATE_LIMITS.mfaPerEmail, ticket.email)
  // Passkey-first lands here too: a user-verified passkey is already two factors.
  return finish(step, result.user, result.tokens)
}

async function enrollPasskey(step: Step): Promise<AuthFormState> {
  const { deps, token, ticket } = step
  if (!ticket.verified) return failed("invalid_request")
  const response = passkeyResponse(step.formData)
  if (!response) return failed("invalid_request")

  const result = await deps.idp.verifyPasskeyRegistration(ticket.idpTransaction, response)
  if (result.ok) return finishVerified(step)
  const options = await deps.idp.passkeyRegistrationOptions(ticket.idpTransaction)
  if (!options.ok) return finishVerified(step)
  return {
    status: "enroll",
    ticket: token,
    options: options.options,
    message: "That passkey couldn't be saved. Try again, or continue without one.",
  }
}

/**
 * The login form's single Server Action. `intent` picks the step; every step after
 * the password carries the ticket. The previous client state is never trusted.
 */
export async function runLoginStep(deps: AuthFlowDeps, request: AuthRequest): Promise<AuthFormState> {
  const intent = field(request.formData, "intent") || "password"
  if (intent === "password") return runLogin(deps, request)

  const parentOrigin = parseAllowedParentOrigin(field(request.formData, "parent"), deps.allowedParentOrigins)
  if (!parentOrigin) return { status: "error", message: INVALID_EMBED }
  const token = field(request.formData, "ticket")
  const ticket = token ? await readMfaTicket(deps.store, token, parentOrigin) : undefined
  if (!ticket) return failed("invalid_grant")

  const step: Step = { ...request, deps, token, ticket, parentOrigin }
  switch (intent) {
    case "send_otp":
      return sendOtp(deps, token, ticket)
    case "verify_otp":
      return verifyOtp(step)
    case "passkey":
      return verifyPasskey(step)
    case "enroll":
      return enrollPasskey(step)
    case "skip_enroll":
      return finishVerified(step)
    default:
      return failed("invalid_request")
  }
}

export type PasskeyChallenge = { ticket: string; options: PasskeyOptions }

/**
 * Starts a passkey-first login: a challenge for any discoverable passkey. The login
 * page fetches it on load, so clicking the button can call the browser immediately.
 */
export async function startPasskeyLogin(
  deps: AuthFlowDeps,
  { parent, ip }: { parent: string; ip: string }
): Promise<PasskeyChallenge | null> {
  const parentOrigin = parseAllowedParentOrigin(parent, deps.allowedParentOrigins)
  if (!parentOrigin) return null
  const limit = await hitRateLimit(deps.store, RATE_LIMITS.passkeyPerIp, ip)
  if (!limit.allowed) return null

  const result = await deps.idp.passkeyAuthenticationOptions()
  if (!result.ok) return null
  const ticket = await mintMfaTicket(deps.store, {
    kind: "passkey",
    idpTransaction: result.transaction,
    parentOrigin,
    hasPasskey: true,
  })
  return { ticket, options: result.options }
}
