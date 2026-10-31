/**
 * The chatbot passes its own origin as `?parent=`. It's only trusted after an
 * exact match against ALLOWED_PARENT_ORIGINS, and it's the only targetOrigin
 * the iframe ever posts to.
 */
export function parseAllowedParentOrigin(value: unknown, allowlist: readonly string[]): string | undefined {
  if (typeof value !== "string" || !URL.canParse(value)) return undefined
  // Exact string match only: no normalization that could let "https://chat.example.com.evil" through.
  return allowlist.includes(value) && new URL(value).origin === value ? value : undefined
}

const NONCE_PATTERN = /^[A-Za-z0-9_-]{16,128}$/

/** The chatbot's per-attempt nonce, echoed back in every message so it can match replies. */
export function parseNonce(value: unknown): string | undefined {
  return typeof value === "string" && NONCE_PATTERN.test(value) ? value : undefined
}
