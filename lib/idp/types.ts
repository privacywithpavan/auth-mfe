export type IdpUser = {
  sub: string
  email: string
  name: string
  emailVerified: boolean
}

export type IdpTokens = {
  accessToken: string
  refreshToken?: string
  idToken?: string
  /** Epoch milliseconds when the access token expires. */
  expiresAt: number
  /**
   * Short-lived session JWT for the org's apps (aud = SESSION_TOKEN_AUDIENCE). Set as the
   * domain-wide auth_token cookie; the chatbot backend verifies it against the IdP's JWKS.
   */
  sessionToken: string
  /** Epoch milliseconds when the session JWT expires (its `exp`). */
  sessionTokenExpiresAt: number
}

export type IdpError =
  /** Wrong email or password. Deliberately doesn't say which. */
  | "invalid_credentials"
  | "email_taken"
  | "weak_password"
  | "invalid_request"
  | "locked"
  /** Refresh token or MFA transaction is expired, revoked or unknown. */
  | "invalid_grant"
  /** Wrong or expired email one-time code. The transaction stays usable. */
  | "invalid_code"
  /** The passkey response didn't verify (unknown credential, wrong user, no user verification…). */
  | "passkey_failed"
  /** IdP unreachable, misconfigured, or returned something unexpected. */
  | "unavailable"

export type IdpResult = { ok: true; user: IdpUser; tokens: IdpTokens } | { ok: false; error: IdpError }

/** Password was right, but the IdP wants a second factor before it issues tokens. */
export type IdpMfaRequired = {
  ok: "mfa_required"
  /** IdP-side login transaction; every second-factor call references it. */
  transaction: string
  hasPasskey: boolean
}

/**
 * WebAuthn options as JSON (PublicKeyCredentialCreationOptionsJSON or
 * ...RequestOptionsJSON). Opaque to the BFF: the IdP makes them and the browser uses them.
 */
export type PasskeyOptions = Record<string, unknown>
/** The browser's credential as JSON (RegistrationResponseJSON or AuthenticationResponseJSON). */
export type PasskeyResponse = Record<string, unknown>

export type IdpVoidResult = { ok: true } | { ok: false; error: IdpError }

/** Everything the BFF needs from the in-house IdP. Only implementations know its wire format. */
export interface IdpClient {
  login(input: { email: string; password: string }): Promise<IdpResult | IdpMfaRequired>
  register(input: { email: string; password: string; name: string }): Promise<IdpResult>
  refresh(refreshToken: string): Promise<IdpResult>
  /** Best effort: revokes the refresh token at the IdP. */
  logout(tokens: IdpTokens): Promise<void>

  /** Emails a one-time code for a password login's second factor. */
  sendEmailOtp(transaction: string): Promise<IdpVoidResult>
  /** Completes the second factor with the emailed code. Also allows passkey enrollment on the transaction. */
  verifyEmailOtp(transaction: string, code: string): Promise<IdpResult>

  /** Options for creating a passkey. Only after the transaction's second factor passed. */
  passkeyRegistrationOptions(transaction: string): Promise<{ ok: true; options: PasskeyOptions } | { ok: false; error: IdpError }>
  verifyPasskeyRegistration(transaction: string, response: PasskeyResponse): Promise<IdpVoidResult>

  /**
   * Options for signing in with a passkey. With a transaction it's the second factor for
   * that user; without one it starts a passkey-first login for any discoverable passkey.
   */
  passkeyAuthenticationOptions(
    transaction?: string
  ): Promise<{ ok: true; transaction: string; options: PasskeyOptions } | { ok: false; error: IdpError }>
  verifyPasskeyAuthentication(transaction: string, response: PasskeyResponse): Promise<IdpResult>
}
