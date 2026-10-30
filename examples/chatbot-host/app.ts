import {
  AuthMfeError,
  logoutAuthSession,
  openAuthMfe,
  refreshAuthSession,
  type AuthMfePage,
} from "@/packages/chatbot-sdk/src"

declare const __AUTH_ORIGIN__: string

type User = { name: string; email: string }

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T
const signedOut = $("signed-out")
const signedIn = $("signed-in")
const frame = $("auth-frame")
const status = $("status")

function render(user: User | null) {
  signedOut.hidden = !!user
  signedIn.hidden = !user
  if (user) $("user-name").textContent = `${user.name} (${user.email})`
}

/**
 * Who's signed in, per our backend. The auth_token JWT is short-lived: on 401, ask the auth
 * BFF to re-issue it from its session once, then retry.
 */
async function fetchUser(): Promise<User | null> {
  let me = await fetch("/api/me")
  if (me.status === 401 && (await refreshAuthSession({ authOrigin: __AUTH_ORIGIN__ }))) me = await fetch("/api/me")
  return me.ok ? (await me.json()).user : null
}

function showStatus(message: string) {
  status.textContent = message
  status.hidden = !message
}

async function login(page: AuthMfePage) {
  showStatus("")
  // Show the MFE inline, in place of the Login buttons.
  signedOut.hidden = true
  frame.hidden = false
  try {
    const result = await openAuthMfe({ authOrigin: __AUTH_ORIGIN__, container: frame, page })
    if (result.status === "cancelled") return render(null)

    // The auth_token cookie is set; OUR backend verifies it.
    const user = await fetchUser()
    if (!user) throw new Error("Couldn't complete sign-in.")
    render(user)
  } catch (error) {
    render(null)
    showStatus(
      error instanceof AuthMfeError
        ? `Sign-in is unavailable right now (${error.reason}).`
        : (error as Error).message
    )
  } finally {
    frame.hidden = true
  }
}

$("login").addEventListener("click", () => login("login"))
$("register").addEventListener("click", () => login("register"))

$("logout").addEventListener("click", async () => {
  try {
    await logoutAuthSession({ authOrigin: __AUTH_ORIGIN__ })
    render(null)
  } catch {
    showStatus("Couldn't sign out. Try again.")
  }
})

render(await fetchUser().catch(() => null))
