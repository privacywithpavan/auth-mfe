import type { ReactNode } from "react"

/** Embedded in the chatbot's iframe: no page chrome, just the centered card. */
export default function AuthLayout({ children }: { children: ReactNode }) {
  return <main className="flex flex-1 items-start justify-center bg-background p-4 sm:items-center">{children}</main>
}
