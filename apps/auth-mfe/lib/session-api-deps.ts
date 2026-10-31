import "server-only"

import { getConfig } from "./config"
import type { SessionApiDeps } from "./session-api"
import { clearAuthTokenCookie, endSession, getCurrentSession, setAuthTokenCookie } from "./session-cookie"

export function sessionApiDeps(): SessionApiDeps {
  return {
    allowedParentOrigins: getConfig().ALLOWED_PARENT_ORIGINS,
    getCurrentSession,
    setAuthTokenCookie,
    clearAuthTokenCookie,
    endSession,
  }
}
