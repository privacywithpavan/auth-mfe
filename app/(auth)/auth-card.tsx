import { Suspense, type ReactNode } from "react"

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Spinner } from "@/components/ui/spinner"

import { EmbedGate } from "./embed-gate"

/**
 * Shared frame for /login and /register. The heading is in the static shell; the
 * form streams in once `?parent=` and `?nonce=` are validated.
 */
export function AuthCard({
  title,
  description,
  searchParams,
  children,
}: {
  title: string
  description: string
  searchParams: Promise<Record<string, string | string[] | undefined>>
  children: ReactNode
}) {
  return (
    <Card className="w-full max-w-sm">
      <CardHeader>
        <CardTitle className="text-lg">{title}</CardTitle>
        <CardDescription>{description}</CardDescription>
      </CardHeader>
      <CardContent>
        <Suspense
          fallback={
            <div className="flex justify-center py-10">
              <Spinner className="size-6 text-muted-foreground" />
            </div>
          }
        >
          <EmbedGate searchParams={searchParams}>{children}</EmbedGate>
        </Suspense>
      </CardContent>
    </Card>
  )
}
