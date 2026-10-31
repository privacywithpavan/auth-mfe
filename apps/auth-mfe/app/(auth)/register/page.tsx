import type { Metadata } from "next"

import { AuthCard } from "../auth-card"
import { RegisterForm } from "./register-form"

export const metadata: Metadata = { title: "Create account" }

export default function Register({ searchParams }: PageProps<"/register">) {
  return (
    <AuthCard
      title="Create an account"
      description="Save your conversations across devices."
      searchParams={searchParams}
    >
      <RegisterForm />
    </AuthCard>
  )
}
