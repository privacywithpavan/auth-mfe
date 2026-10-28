import "server-only"

import { getConfig } from "./config"
import type { HandoffApiDeps } from "./handoff-api"
import { getIdpClient } from "./idp"
import { getStore } from "./store"

export function handoffApiDeps(): HandoffApiDeps {
  const config = getConfig()
  return {
    store: getStore(),
    idp: getIdpClient(),
    clientId: config.HANDOFF_CLIENT_ID,
    clientSecret: config.HANDOFF_CLIENT_SECRET,
  }
}
