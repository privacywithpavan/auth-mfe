import { NextResponse, type NextRequest } from "next/server"

import { getConfig } from "@/lib/config"
import { securityHeaders } from "@/lib/security-headers"

export function proxy(request: NextRequest) {
  const config = getConfig()
  const response = NextResponse.next()
  const headers = securityHeaders(request.nextUrl.pathname, {
    allowedParentOrigins: config.ALLOWED_PARENT_ORIGINS,
    production: config.NODE_ENV === "production",
  })
  for (const [name, value] of Object.entries(headers)) response.headers.set(name, value)
  return response
}

export const config = {
  // Skip build assets; they're served with their own caching headers.
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
}
