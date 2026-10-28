/**
 * Runs the mock in-house IdP (see ./idp.ts for its API). Never deploy this.
 *
 *   npm run mock-idp
 *
 * MOCK_IDP_PORT           listen port (default 9000)
 * MOCK_IDP_CLIENT_ID      client id the BFF must present (default auth-mfe)
 * MOCK_IDP_CLIENT_SECRET  client secret (default dev-client-secret)
 */
import { createMockIdp } from "./idp"

async function main() {
  const clientId = process.env.MOCK_IDP_CLIENT_ID
  const idp = await createMockIdp({ clientId, clientSecret: process.env.MOCK_IDP_CLIENT_SECRET })
  const issuer = await idp.start(Number(process.env.MOCK_IDP_PORT ?? 9000))
  console.log(`Mock IdP: ${issuer} (client ${clientId ?? "auth-mfe"})`)
}

main().catch((error) => {
  console.error(error)
  process.exit(1)
})
