import js from "@eslint/js"
import { defineConfig, globalIgnores } from "eslint/config"
import tseslint from "typescript-eslint"

/** For TypeScript packages and Node apps that aren't Next.js. */
export default defineConfig([
  js.configs.recommended,
  ...tseslint.configs.recommended,
  globalIgnores(["dist/**", "certificates/**"]),
])
