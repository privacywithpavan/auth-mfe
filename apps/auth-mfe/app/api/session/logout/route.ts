import { handleLogout, handlePreflight } from "@/lib/session-api"
import { sessionApiDeps } from "@/lib/session-api-deps"

/** Chatbot page ends the session. See lib/session-api.ts. */
export async function POST(request: Request) {
  return handleLogout(request, sessionApiDeps())
}

export function OPTIONS(request: Request) {
  return handlePreflight(request, sessionApiDeps())
}
