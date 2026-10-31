# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

An authentication micro-frontend with its own BFF, the mock IdP it talks to locally, and a reference chatbot that embeds it. pnpm workspaces + Turborepo.

The chatbot embeds `/login` (or `/register`) from `apps/auth-mfe/app/(auth)/` in an iframe. The forms submit through Server Actions, and the BFF calls the IdP's login and sign-up API server-to-server, then keeps the tokens in its own session. The IdP is the mock in `apps/mock-idp/` for now and the in-house IdP later; all IdP calls go through the adapter in `apps/auth-mfe/lib/idp/`, and the wire format lives in `packages/idp-contract`. The chatbot and the MFE share an org root domain (`SESSION_COOKIE_DOMAIN`): after login the BFF sets a domain-wide, HttpOnly `auth_token` cookie holding the IdP's short-lived session JWT, which the chatbot's backend verifies against the IdP's JWKS with `@auth-mfe/token-verifier`; the chatbot page renews it through `POST /api/session/refresh` and ends it with `/api/session/logout`. `postMessage` only signals success. See `docs/auth-flow.md`.

## Layout

| Path | Package | What |
|---|---|---|
| `apps/auth-mfe` | `@auth-mfe/app` | Next.js 16 App Router + React 19 BFF. The only deployable |
| `apps/mock-idp` | `@auth-mfe/mock-idp` | Mock IdP on http://localhost:9000 (alice@example.com / password123; OTP codes print to its console). Also imported in-process by the BFF's tests. Never deploy |
| `apps/chatbot-host` | `@auth-mfe/chatbot-host` | Example chatbot on https://chat.localtest.me:4000 (frontend + backend). Never deploy |
| `packages/sdk` | `@auth-mfe/sdk` | Chatbot-side SDK (`openAuthMfe`, `refreshAuthSession`, `logoutAuthSession`) and the postMessage protocol (`@auth-mfe/sdk/protocol`, re-exported by `apps/auth-mfe/lib/protocol.ts`) |
| `packages/token-verifier` | `@auth-mfe/token-verifier` | Server-side `auth_token` check for chatbot backends; also owns the cookie name |
| `packages/idp-contract` | `@auth-mfe/idp-contract` | IdP API paths, error codes and payload types, shared by the BFF adapter and the mock |
| `packages/dev-certs` | `@auth-mfe/dev-certs` | mkcert certificates for non-Next dev servers |
| `packages/tsconfig`, `packages/eslint-config` | | Shared configs (`base`/`node`/`browser`/`nextjs`; `base`/`next`) |

Workspace packages export their TypeScript source (`exports` → `src/*.ts`), so nothing needs building in dev; Turbopack, Vitest, tsx and esbuild compile it. `sdk` and `token-verifier` also build to `dist/` with tsdown, and `publishConfig.exports` points the published package there.

## Commands

```bash
pnpm install
pnpm dev            # all three apps in turbo's terminal UI, one log pane each (needs apps/auth-mfe/.env.local)
pnpm dev:auth | dev:idp | dev:chat     # one app per terminal, plain output
pnpm build | lint | typecheck | test   # via turbo, across the workspace
pnpm --filter @auth-mfe/app exec vitest run lib/config.test.ts -t "rejects"   # single file / single test
cd apps/auth-mfe && pnpm dlx shadcn@latest add <component>   # add a shadcn/ui component into components/ui
```

`next dev --experimental-https` serves the MFE on https://auth.localtest.me:3000 (mkcert certs in `apps/auth-mfe/certificates`); run it once before the chatbot host, which reuses its mkcert CA.

Env: each app has its own `.env.example`; copy to `.env.local` in that app's directory. Only the auth MFE needs one; the others default to the local setup. The MFE's config is validated by `getConfig()` in `apps/auth-mfe/lib/config.ts` (zod); add new env vars there. Turbo runs tasks in strict env mode: an env var a task needs from the shell has to be listed in `turbo.json`. `server-only` is aliased to an empty module in `apps/auth-mfe/vitest.config.mts` so server modules are testable. pnpm only runs dependency build scripts listed under `allowBuilds` in `pnpm-workspace.yaml`.

## Next.js version caveats

Next 16.4 differs from older versions — consult `apps/auth-mfe/node_modules/next/dist/docs/` (App Router docs under `01-app/`) before using any API. Notable settings in `apps/auth-mfe/next.config.ts`:

- `cacheComponents: true` + `partialPrefetching: true` — data fetching is dynamic by default; opt into caching with the `use cache` directive, `cacheLife`, and `cacheTag`. Route segment `runtime` exports (including `'edge'`) are not supported. For auth patterns under this model, read `01-app/02-guides/authentication-with-cache-components.md`.
- `experimental.agentFeedback: true` — `next dev` regenerates the block in `apps/auth-mfe/AGENTS.md`; don't hand-edit that block.
- Tailwind CSS v4 is wired through a Turbopack CSS loader rule (`@tailwindcss/turbopack`), not PostCSS. There is no `tailwind.config` — theme tokens live in `app/globals.css` (`@theme inline` + CSS variables, dark mode via the `.dark` class variant).
- Layouts/pages use the global, generated `LayoutProps<"/">` / `PageProps<...>` route types; `typecheck` runs `next typegen` first so they exist on a clean checkout.
- Turbopack transpiles the workspace packages automatically; no `transpilePackages` needed.

## UI conventions

- shadcn/ui with the `base-nova` style: primitives come from **Base UI** (`@base-ui/react`), not Radix. Components in `components/ui/` wrap Base UI primitives, use `cva` for variants, and set a `data-slot` attribute.
- `cn` comes from the `cn` npm package (re-exported by `lib/utils.ts`), not the usual `clsx` + `tailwind-merge` helper.
- Icons: `lucide-react`. In the auth MFE, path alias `@/*` maps to `apps/auth-mfe/` (`@/components`, `@/lib`, `@/components/ui`, `@/hooks`).
