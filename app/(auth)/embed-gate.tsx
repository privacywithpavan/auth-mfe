import type { ReactNode } from "react"
import { CircleAlertIcon } from "lucide-react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { getConfig } from "@/lib/config"
import { parseAllowedParentOrigin, parseNonce } from "@/lib/origins"

import { EmbedProvider } from "./embed-context"

/**
 * Validates `?parent=` against the allowlist and `?nonce=` before rendering a form.
 * Reads request data, so it must render inside <Suspense>.
 */
export async function EmbedGate({
  searchParams,
  children,
}: {
  searchParams: Promise<Record<string, string | string[] | undefined>>
  children: ReactNode
}) {
  const { parent, nonce } = await searchParams
  const parentOrigin = parseAllowedParentOrigin(parent, getConfig().ALLOWED_PARENT_ORIGINS)
  const validNonce = parseNonce(nonce)

  if (!parentOrigin || !validNonce) {
    // No trusted origin to report to, so there's no postMessage here.
    return (
      <Alert variant="destructive">
        <CircleAlertIcon />
        <AlertTitle>Can&apos;t sign in here</AlertTitle>
        <AlertDescription>Open sign-in from the chatbot to continue.</AlertDescription>
      </Alert>
    )
  }

  return (
    <EmbedProvider parentOrigin={parentOrigin} nonce={validNonce}>
      {children}
    </EmbedProvider>
  )
}
