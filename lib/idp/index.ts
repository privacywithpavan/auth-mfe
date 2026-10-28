import "server-only"

import { getConfig } from "@/lib/config"

import { createHttpIdpClient } from "./http-client"
import type { IdpClient } from "./types"

export type * from "./types"

let client: IdpClient | undefined

export function getIdpClient(): IdpClient {
  if (!client) {
    const config = getConfig()
    client = createHttpIdpClient({
      baseUrl: config.IDP_BASE_URL,
      issuer: config.IDP_ISSUER,
      jwksUrl: config.IDP_JWKS_URL,
      clientId: config.IDP_CLIENT_ID,
      clientSecret: config.IDP_CLIENT_SECRET,
    })
  }
  return client
}
