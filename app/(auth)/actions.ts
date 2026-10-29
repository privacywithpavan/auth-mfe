"use server"

import "server-only"
import { headers } from "next/headers"

import { runLoginStep, runRegister, startPasskeyLogin, type AuthFlowDeps, type PasskeyChallenge } from "@/lib/auth-flow"
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

/** Every login step: password, second factor, passkey, passkey enrollment. */
export async function loginAction(_previous: AuthFormState, formData: FormData): Promise<AuthFormState> {
  return runLoginStep(deps(), { formData, ip: await clientIp() })
}

/** A fresh passkey-first challenge, or null when passkeys can't be offered right now. */
export async function passkeyChallengeAction(parent: string): Promise<PasskeyChallenge | null> {
  return startPasskeyLogin(deps(), { parent: String(parent), ip: await clientIp() })
}

export async function registerAction(_previous: AuthFormState, formData: FormData): Promise<AuthFormState> {
  return runRegister(deps(), { formData, ip: await clientIp() })
}
