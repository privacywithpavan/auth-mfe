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
}

export type IdpError =
  /** Wrong email or password. Deliberately doesn't say which. */
  | "invalid_credentials"
  | "email_taken"
  | "weak_password"
  | "invalid_request"
  | "locked"
  /** Refresh token is expired, revoked or unknown. */
  | "invalid_grant"
  /** IdP unreachable, misconfigured, or returned something unexpected. */
  | "unavailable"

export type IdpResult = { ok: true; user: IdpUser; tokens: IdpTokens } | { ok: false; error: IdpError }

/** Everything the BFF needs from the in-house IdP. Only implementations know its wire format. */
export interface IdpClient {
  login(input: { email: string; password: string }): Promise<IdpResult>
  register(input: { email: string; password: string; name: string }): Promise<IdpResult>
  refresh(refreshToken: string): Promise<IdpResult>
  /** Best effort: revokes the refresh token at the IdP. */
  logout(tokens: IdpTokens): Promise<void>
}
