/**
 * Wire contract of the in-house IdP API that the auth BFF calls server-to-server.
 * The BFF's adapter (apps/auth-mfe/lib/idp/http-client.ts) and the mock IdP
 * (apps/mock-idp) both build on these definitions, so the in-house IdP team can
 * implement against one source.
 *
 * Every call authenticates the client with HTTP Basic (client id + secret). Bodies
 * are JSON, except the OAuth refresh grant on `token`, which is form-encoded.
 *
 *   login                        LoginRequest                     → 200 TokenResponse | LoginMfaRequiredResponse | 401 invalid_credentials | 423 locked
 *   register                     RegisterRequest                  → 201 TokenResponse | 409 email_taken | 400 weak_password | 400 invalid_request
 *   logout                       LogoutRequest                    → 204
 *   token                        RefreshTokenRequest (form)       → 200 TokenResponse | 400 invalid_grant
 *   otpSend                      MfaTokenRequest                  → 204 | 400 invalid_grant
 *   otpVerify                    OtpVerifyRequest                 → 200 TokenResponse | 400 invalid_code | 400 invalid_grant
 *   passkeyRegistrationOptions   MfaTokenRequest                  → 200 PasskeyRegistrationOptionsResponse | 403 invalid_grant
 *   passkeyRegistrationVerify    PasskeyRegistrationVerifyRequest → 204 | 400 passkey_failed | 400 invalid_grant
 *   passkeyAuthenticationOptions Partial<MfaTokenRequest>         → 200 PasskeyAuthenticationOptionsResponse | 400 invalid_grant | 400 invalid_request
 *   passkeyAuthenticationVerify  PasskeyAuthenticationVerifyRequest → 200 TokenResponse | 400 passkey_failed | 400 invalid_grant
 *
 * Errors are `ErrorResponse`. Bad client credentials are 401 `invalid_client`.
 * The IdP also serves `/jwks` and `/.well-known/openid-configuration`.
 */

export const IDP_PATHS = {
  login: "/api/login",
  register: "/api/register",
  logout: "/api/logout",
  token: "/token",
  otpSend: "/api/mfa/otp/send",
  otpVerify: "/api/mfa/otp/verify",
  passkeyRegistrationOptions: "/api/passkeys/registration/options",
  passkeyRegistrationVerify: "/api/passkeys/registration/verify",
  passkeyAuthenticationOptions: "/api/passkeys/authentication/options",
  passkeyAuthenticationVerify: "/api/passkeys/authentication/verify",
} as const

/** Errors caused by user input or login state. The BFF passes these through to the UI. */
export const IDP_ERROR_CODES = [
  /** Wrong email or password. Deliberately doesn't say which. */
  "invalid_credentials",
  "email_taken",
  "weak_password",
  "invalid_request",
  "locked",
  /** Refresh token or MFA transaction is expired, revoked or unknown. */
  "invalid_grant",
  /** Wrong or expired email one-time code. The transaction stays usable. */
  "invalid_code",
  /** The passkey response didn't verify (unknown credential, wrong user, no user verification…). */
  "passkey_failed",
] as const

export type IdpErrorCode = (typeof IDP_ERROR_CODES)[number]

export type ErrorResponse = {
  /** `invalid_client` means the BFF's client credentials are wrong: a misconfiguration, not user input. */
  error: IdpErrorCode | "invalid_client"
}

/**
 * Every token response: login, second factor, passkey, register and the refresh grant.
 * `session_token` is the short-lived JWT the BFF sets as the domain-wide auth_token cookie.
 */
export type TokenResponse = {
  token_type: "Bearer"
  access_token: string
  /** Its `aud` is the BFF's client id. */
  id_token: string
  /** Rotated on every refresh grant. */
  refresh_token: string
  session_token: string
  /** Access token lifetime in seconds. */
  expires_in: number
}

/** Claims of `session_token`. Signed RS256 with a key from the IdP's JWKS. */
export type SessionTokenClaims = {
  iss: string
  /** The session token audience, e.g. "chatbot". */
  aud: string
  /** Same as the ID token's `sub`. */
  sub: string
  email: string
  name: string
  jti: string
  iat: number
  exp: number
}

export type LoginRequest = { email: string; password: string }

/** The password was right, but a second factor is needed before tokens are issued. */
export type LoginMfaRequiredResponse = {
  mfa_required: true
  /** The login transaction (5 minutes); every second-factor call references it. */
  mfa_token: string
  has_passkey: boolean
}

export type RegisterRequest = { email: string; password: string; name: string }

export type LogoutRequest = { refresh_token: string }

export type RefreshTokenRequest = { grant_type: "refresh_token"; refresh_token: string }

export type MfaTokenRequest = { mfa_token: string }

export type OtpVerifyRequest = MfaTokenRequest & { code: string }

/**
 * WebAuthn options as JSON (PublicKeyCredentialCreationOptionsJSON or
 * ...RequestOptionsJSON). Opaque to the BFF: the IdP makes them and the browser uses them.
 */
export type PasskeyOptionsJson = Record<string, unknown>

/** The browser's credential as JSON (RegistrationResponseJSON or AuthenticationResponseJSON). */
export type PasskeyResponseJson = Record<string, unknown>

/** Only after the transaction's second factor passed. */
export type PasskeyRegistrationOptionsResponse = { options: PasskeyOptionsJson }

export type PasskeyRegistrationVerifyRequest = MfaTokenRequest & { response: PasskeyResponseJson }

/**
 * Without `mfa_token` in the request, this starts a passkey-first login for any
 * discoverable passkey, and `transaction` is new.
 */
export type PasskeyAuthenticationOptionsResponse = { transaction: string; options: PasskeyOptionsJson }

export type PasskeyAuthenticationVerifyRequest = { transaction: string; response: PasskeyResponseJson }
