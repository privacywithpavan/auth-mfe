"use client"

import { createContext, use, useCallback, useEffect, useMemo, type ReactNode } from "react"

import { envelope, type AuthMfeMessage } from "@/lib/protocol"

type DistributiveOmit<T, K extends PropertyKey> = T extends unknown ? Omit<T, K> : never
type OutgoingMessage = DistributiveOmit<AuthMfeMessage, "nonce">

type EmbedContextValue = {
  parentOrigin: string
  nonce: string
  /** `?parent=…&nonce=…`, for links between /login and /register. */
  query: string
  post: (message: OutgoingMessage) => void
}

const EmbedContext = createContext<EmbedContextValue | null>(null)

/**
 * Holds the validated parent origin and nonce, and is the only place that calls
 * postMessage. Always targets the exact parent origin, never "*".
 */
export function EmbedProvider({
  parentOrigin,
  nonce,
  children,
}: {
  parentOrigin: string
  nonce: string
  children: ReactNode
}) {
  const post = useCallback(
    (message: OutgoingMessage) => {
      if (window.parent === window) return // opened directly, nobody to tell
      window.parent.postMessage(envelope({ ...message, nonce } as AuthMfeMessage), parentOrigin)
    },
    [parentOrigin, nonce]
  )

  useEffect(() => {
    post({ type: "auth:ready" })
    const observer = new ResizeObserver(() => {
      post({ type: "auth:resize", height: Math.ceil(document.documentElement.scrollHeight) })
    })
    observer.observe(document.body)
    return () => observer.disconnect()
  }, [post])

  const value = useMemo(
    () => ({
      parentOrigin,
      nonce,
      query: new URLSearchParams({ parent: parentOrigin, nonce }).toString(),
      post,
    }),
    [parentOrigin, nonce, post]
  )

  return <EmbedContext value={value}>{children}</EmbedContext>
}

export function useEmbed() {
  const value = use(EmbedContext)
  if (!value) throw new Error("useEmbed must be used within an EmbedProvider")
  return value
}
