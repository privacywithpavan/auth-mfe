import { z } from "zod"

const email = z.string().trim().toLowerCase().pipe(z.email({ message: "Enter a valid email address." }))

export const loginSchema = z.object({
  email,
  password: z.string().min(1, "Enter your password.").max(128, "Password is too long."),
})

export const registerSchema = z
  .object({
    name: z.string().trim().min(1, "Enter your name.").max(100, "Name is too long."),
    email,
    password: z
      .string()
      .min(8, "Use at least 8 characters.")
      .max(128, "Use at most 128 characters."),
    confirmPassword: z.string(),
  })
  .refine((value) => value.password === value.confirmPassword, {
    path: ["confirmPassword"],
    message: "Passwords don't match.",
  })

export type LoginInput = z.infer<typeof loginSchema>
export type RegisterInput = z.infer<typeof registerSchema>

export type FormField = "name" | "email" | "password" | "confirmPassword"

/** What a login/register Server Action returns to its form. Never contains passwords. */
export type AuthFormState =
  | { status: "idle" }
  | {
      status: "error"
      message?: string
      fieldErrors?: Partial<Record<FormField, string>>
      /** Re-fills non-secret fields after React resets the form. */
      values?: { email?: string; name?: string }
    }
  | { status: "success"; code: string; user: { name: string; email: string } }

export const initialAuthFormState: AuthFormState = { status: "idle" }
