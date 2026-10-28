import { handleExchange } from "@/lib/handoff-api"
import { handoffApiDeps } from "@/lib/handoff-api-deps"

/** Chatbot backend redeems a one-time handoff code. See lib/handoff-api.ts. */
export async function POST(request: Request) {
  return handleExchange(request, handoffApiDeps())
}
