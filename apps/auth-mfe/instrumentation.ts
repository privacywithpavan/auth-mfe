/** Fail at startup, not on the first request, when the environment is misconfigured. */
export async function register() {
  // The build doesn't need runtime secrets; they're checked when the server starts.
  if (process.env.NEXT_PHASE === "phase-production-build") return
  if (process.env.NEXT_RUNTIME !== "nodejs") return
  const { getConfig } = await import("./lib/config")
  getConfig()
}
