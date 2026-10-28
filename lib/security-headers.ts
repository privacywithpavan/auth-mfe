/** Pages the chatbot may frame. Everything else refuses to be framed at all. */
export const EMBEDDABLE_PATHS = ["/login", "/register"]

export function isEmbeddablePath(pathname: string) {
  return EMBEDDABLE_PATHS.some((path) => pathname === path || pathname === `${path}/`)
}

/**
 * Response headers for every request. Framing is the main control: only the
 * allowlisted chatbot origins can embed /login and /register, so other sites
 * can't overlay or clickjack the forms.
 */
export function securityHeaders(
  pathname: string,
  { allowedParentOrigins, production }: { allowedParentOrigins: readonly string[]; production: boolean }
): Record<string, string> {
  const embeddable = isEmbeddablePath(pathname)
  const frameAncestors = embeddable ? allowedParentOrigins.join(" ") : "'none'"

  const headers: Record<string, string> = {
    "Content-Security-Policy": [
      `frame-ancestors ${frameAncestors}`,
      "base-uri 'self'",
      "form-action 'self'",
      "object-src 'none'",
    ].join("; "),
    "Referrer-Policy": "same-origin",
    "X-Content-Type-Options": "nosniff",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
  }
  // X-Frame-Options can't express an allowlist; browsers that support CSP ignore it anyway.
  if (!embeddable) headers["X-Frame-Options"] = "DENY"
  if (production) headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
  return headers
}
