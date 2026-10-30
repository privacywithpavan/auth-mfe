/**
 * Runs the mock in-house IdP (see ./idp.ts for its API). Never deploy this.
 *
 *   npm run mock-idp
 *
 * MOCK_IDP_PORT           listen port (default 9000)
 * MOCK_IDP_CLIENT_ID      client id the BFF must present (default auth-mfe)
 * MOCK_IDP_CLIENT_SECRET  client secret (default dev-client-secret)
 * MOCK_IDP_RP_ID          WebAuthn RP ID (default auth.localtest.me)
 * MOCK_IDP_ORIGIN         origin passkey ceremonies must come from (default https://auth.localtest.me:3000)
 * MOCK_IDP_REQUIRE_MFA    "false" lets password logins skip the second factor
 * MOCK_IDP_SESSION_AUDIENCE     aud of the session JWT (default chatbot)
 * MOCK_IDP_SESSION_TTL_SECONDS  session JWT lifetime (default 600); lower it to exercise refresh
 *
 * Emailed one-time codes are printed to the console.
 */
import { createMockIdp } from "./idp"

async function main() {
  const clientId = process.env.MOCK_IDP_CLIENT_ID
  const idp = await createMockIdp({
    clientId,
    clientSecret: process.env.MOCK_IDP_CLIENT_SECRET,
    rpId: process.env.MOCK_IDP_RP_ID,
    expectedOrigin: process.env.MOCK_IDP_ORIGIN,
    requireMfa: process.env.MOCK_IDP_REQUIRE_MFA !== "false",
    sessionAudience: process.env.MOCK_IDP_SESSION_AUDIENCE,
    sessionTokenTtlSeconds: process.env.MOCK_IDP_SESSION_TTL_SECONDS
      ? Number(process.env.MOCK_IDP_SESSION_TTL_SECONDS)
      : undefined,
  })
  const issuer = await idp.start(Number(process.env.MOCK_IDP_PORT ?? 9000))
  console.log(`Mock IdP: ${issuer} (client ${clientId ?? "auth-mfe"})`)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
