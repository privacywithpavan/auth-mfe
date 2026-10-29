import { vi } from "vitest"

import type { IdpClient, IdpTokens, IdpUser } from "./idp/types"

export const alice: IdpUser = {
  sub: "mock-user-alice",
  email: "alice@example.com",
  name: "Alice Example",
  emailVerified: true,
}

export function tokens(overrides: Partial<IdpTokens> = {}): IdpTokens {
  return {
    accessToken: "access",
    refreshToken: "refresh",
    idToken: "id",
    expiresAt: Date.now() + 3600_000,
    ...overrides,
  }
}

/** IdpClient whose methods are vi.fn()s; override per test. */
export function fakeIdp(overrides: Partial<IdpClient> = {}) {
  return {
    login: vi.fn(),
    register: vi.fn(),
    refresh: vi.fn(),
    logout: vi.fn(async () => {}),
    sendEmailOtp: vi.fn(),
    verifyEmailOtp: vi.fn(),
    passkeyRegistrationOptions: vi.fn(),
    verifyPasskeyRegistration: vi.fn(),
    passkeyAuthenticationOptions: vi.fn(),
    verifyPasskeyAuthentication: vi.fn(),
    ...overrides,
  } satisfies IdpClient
}
