import { AuthMfeError, openAuthMfe, type AuthMfePage } from "@/packages/chatbot-sdk/src"

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

    // Hand the one-time code to OUR backend; it redeems it server-to-server.
    const response = await fetch("/api/session", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code: result.code }),
    })
    if (!response.ok) throw new Error("Couldn't complete sign-in.")
    render((await response.json()).user)
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
  await fetch("/api/logout", { method: "POST" })
  render(null)
})

const me = await fetch("/api/me")
render(me.ok ? (await me.json()).user : null)
