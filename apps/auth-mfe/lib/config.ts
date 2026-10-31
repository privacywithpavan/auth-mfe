import "server-only"
import { z } from "zod"

const origin = z.string().refine(
  (value) => URL.canParse(value) && new URL(value).origin === value,
  { message: "must be a bare origin like https://chat.example.com (no path or trailing slash)" }
)

const configSchema = z
  .object({
    NODE_ENV: z.enum(["development", "production", "test"]).default("development"),

    /** Public origin this app is served from, e.g. https://auth.example.com */
    APP_ORIGIN: origin,

    /** Base URL of the IdP API the BFF calls server-to-server. */
    IDP_BASE_URL: z.url(),
    /** Expected `iss` of IdP-issued JWTs; defaults to IDP_BASE_URL. */
    IDP_ISSUER: z.url().optional(),
    /** JWKS used to verify IdP-issued JWTs; defaults to IDP_BASE_URL/jwks. */
    IDP_JWKS_URL: z.url().optional(),
    IDP_CLIENT_ID: z.string().min(1),
    IDP_CLIENT_SECRET: z.string().min(1),

    /** Comma-separated origins allowed to embed /login and /register and receive postMessage results. */
    ALLOWED_PARENT_ORIGINS: z
      .string()
      .transform((value) => value.split(",").map((item) => item.trim()).filter(Boolean))
      .pipe(z.array(origin).min(1)),

    /**
     * Org root domain the auth_token cookie is scoped to, e.g. example.com. The chatbot
     * and this app must both be served from it (or its subdomains).
     */
    SESSION_COOKIE_DOMAIN: z
      .string()
      .regex(/^[a-z0-9-]+(\.[a-z0-9-]+)+$/, { message: "must be a bare domain like example.com" }),
    /** Expected `aud` of the IdP's session JWT; the chatbot backend checks the same value. */
    SESSION_TOKEN_AUDIENCE: z.string().min(1).default("chatbot"),

    SESSION_TTL_SECONDS: z.coerce.number().int().positive().default(8 * 60 * 60),
  })
  .transform((config) => ({
    ...config,
    IDP_ISSUER: config.IDP_ISSUER ?? config.IDP_BASE_URL,
    IDP_JWKS_URL: config.IDP_JWKS_URL ?? `${config.IDP_BASE_URL.replace(/\/+$/, "")}/jwks`,
  }))
  .superRefine((config, ctx) => {
    const domain = config.SESSION_COOKIE_DOMAIN
    for (const value of [config.APP_ORIGIN, ...config.ALLOWED_PARENT_ORIGINS]) {
      const { hostname } = new URL(value)
      if (hostname !== domain && !hostname.endsWith(`.${domain}`)) {
        ctx.addIssue({ code: "custom", message: `${value} must be on SESSION_COOKIE_DOMAIN (${domain})` })
      }
    }
    if (config.NODE_ENV !== "production") return
    for (const value of [config.APP_ORIGIN, config.IDP_BASE_URL, ...config.ALLOWED_PARENT_ORIGINS]) {
      if (!value.startsWith("https://")) {
        ctx.addIssue({ code: "custom", message: `${value} must use https in production` })
      }
    }
  })

export type Config = z.output<typeof configSchema>

export function parseConfig(env: Record<string, string | undefined>): Config {
  const result = configSchema.safeParse(env)
  if (!result.success) {
    throw new Error(`Invalid auth-mfe configuration:\n${z.prettifyError(result.error)}`)
  }
  return result.data
}

let cached: Config | undefined

/** Validated config, read from process.env on first use. */
export function getConfig(): Config {
  cached ??= parseConfig(process.env)
  return cached
}
