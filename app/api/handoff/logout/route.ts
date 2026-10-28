import { handleLogout } from "@/lib/handoff-api"
import { handoffApiDeps } from "@/lib/handoff-api-deps"

/** Chatbot backend ends the user's BFF session. See lib/handoff-api.ts. */
export async function POST(request: Request) {
  return handleLogout(request, handoffApiDeps())
}
