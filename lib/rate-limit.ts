import type { KeyValueStore } from "./store"
import { hashToken } from "./tokens"

export type RateLimitRule = {
  /** Namespace, e.g. "login:ip". */
  name: string
  limit: number
  windowSeconds: number
}

export type RateLimitResult = { allowed: true } | { allowed: false; retryAfterSeconds: number }

/** Login, sign-up and second-factor limits. Per-email limits stop credential stuffing against one account. */
export const RATE_LIMITS = {
  loginPerIp: { name: "login:ip", limit: 20, windowSeconds: 15 * 60 },
  loginPerEmail: { name: "login:email", limit: 5, windowSeconds: 15 * 60 },
  registerPerIp: { name: "register:ip", limit: 5, windowSeconds: 60 * 60 },
  /** Second-factor attempts (codes and passkeys) per account, and code emails per account. */
  mfaPerEmail: { name: "mfa:email", limit: 10, windowSeconds: 15 * 60 },
  otpSendPerEmail: { name: "otp-send:email", limit: 5, windowSeconds: 15 * 60 },
  /** Passkey-first challenges and attempts. Generous: the login page fetches a challenge on load. */
  passkeyPerIp: { name: "passkey:ip", limit: 30, windowSeconds: 15 * 60 },
} satisfies Record<string, RateLimitRule>

function rateLimitKey(rule: RateLimitRule, subject: string) {
  // Hash so emails and IPs aren't stored in the clear.
  return `ratelimit:${rule.name}:${hashToken(subject.toLowerCase())}`
}

/** Fixed-window counter. Each call counts as one attempt. */
export async function hitRateLimit(
  store: KeyValueStore,
  rule: RateLimitRule,
  subject: string
): Promise<RateLimitResult> {
  const { count, expiresAt } = await store.increment(rateLimitKey(rule, subject), rule.windowSeconds)
  if (count <= rule.limit) return { allowed: true }
  return { allowed: false, retryAfterSeconds: Math.max(1, Math.ceil((expiresAt - Date.now()) / 1000)) }
}

/** Clears a counter, e.g. the per-email login counter after a successful login. */
export async function resetRateLimit(store: KeyValueStore, rule: RateLimitRule, subject: string) {
  await store.delete(rateLimitKey(rule, subject))
}
