import { handlePreflight, handleRefresh } from "@/lib/session-api"
import { sessionApiDeps } from "@/lib/session-api-deps"

/** Chatbot page re-issues the auth_token cookie. See lib/session-api.ts. */
export async function POST(request: Request) {
  return handleRefresh(request, sessionApiDeps())
}

export function OPTIONS(request: Request) {
  return handlePreflight(request, sessionApiDeps())
}
