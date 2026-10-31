import type { Metadata } from "next"

import { AuthCard } from "../auth-card"
import { LoginForm } from "./login-form"

export const metadata: Metadata = { title: "Sign in" }

export default function Login({ searchParams }: PageProps<"/login">) {
  return (
    <AuthCard title="Sign in" description="Sign in to keep your conversations." searchParams={searchParams}>
      <LoginForm />
    </AuthCard>
  )
}
