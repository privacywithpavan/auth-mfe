"use server"

import "server-only"
import { headers } from "next/headers"

import { runLogin, runRegister, type AuthFlowDeps } from "@/lib/auth-flow"
import type { AuthFormState } from "@/lib/auth-schemas"
import { getConfig } from "@/lib/config"
import { getIdpClient } from "@/lib/idp"
import { startSession } from "@/lib/session-cookie"
import { getStore } from "@/lib/store"

function deps(): AuthFlowDeps {
  const config = getConfig()
  return {
    store: getStore(),
    idp: getIdpClient(),
    allowedParentOrigins: config.ALLOWED_PARENT_ORIGINS,
    handoffTtlSeconds: config.HANDOFF_CODE_TTL_SECONDS,
    startSession,
  }
}

async function clientIp() {
  // Assumes a trusted proxy in front of the app sets X-Forwarded-For.
  const forwarded = (await headers()).get("x-forwarded-for")
  return forwarded?.split(",")[0]?.trim() || "unknown"
}

export async function loginAction(_previous: AuthFormState, formData: FormData): Promise<AuthFormState> {
  return runLogin(deps(), { formData, ip: await clientIp() })
}

export async function registerAction(_previous: AuthFormState, formData: FormData): Promise<AuthFormState> {
  return runRegister(deps(), { formData, ip: await clientIp() })
}
