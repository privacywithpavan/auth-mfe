# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`auth-mfe` is an authentication micro-frontend with its own BFF (Next.js 16 App Router + React 19). The chatbot embeds `/login` (or `/register`) from `app/(auth)/` in an iframe. The forms submit through Server Actions, and the BFF calls the IdP's login and sign-up API server-to-server, then keeps the tokens in its own session. The IdP is a local mock in `dev/mock-idp/` for now and the in-house IdP later; all IdP calls go through the adapter in `lib/idp/`. The chatbot and the MFE share an org root domain (`SESSION_COOKIE_DOMAIN`): after login the BFF sets a domain-wide, HttpOnly `auth_token` cookie holding the IdP's short-lived session JWT, which the chatbot's backend verifies against the IdP's JWKS; the chatbot page renews it through `POST /api/session/refresh` and ends it with `/api/session/logout`. `postMessage` only signals success. See `docs/auth-flow.md`.

## Commands

```bash
npm run mock-idp    # mock in-house IdP on http://localhost:9000 (alice@example.com / password123)
npm run dev         # next dev over HTTPS on https://auth.localtest.me:3000 (mkcert cert in ./certificates)
npm run chat-host   # example chatbot on https://chat.localtest.me:4000 that embeds the MFE (needs dev + mock-idp)
npm run build       # production build
npm run lint        # ESLint 9 flat config (eslint-config-next core-web-vitals + typescript)
npm run typecheck   # tsc --noEmit
npm test            # Vitest, all *.test.ts
npx vitest run lib/config.test.ts -t "rejects"   # single file / single test
npx shadcn@latest add <component>   # add a shadcn/ui component into components/ui
```

The postMessage protocol and the chatbot-side SDK (`openAuthMfe`) live in `packages/chatbot-sdk/`; `lib/protocol.ts` re-exports the protocol so both sides share one definition. `examples/chatbot-host/` is the reference integration (frontend + backend that verifies the `auth_token` JWT).

Env: copy `.env.example` to `.env.local`. Config is validated by `getConfig()` in `lib/config.ts` (zod); add new env vars there. `server-only` is aliased to an empty module in `vitest.config.mts` so server modules are testable.
## Next.js version caveats

Next 16.4 differs from older versions — consult `node_modules/next/dist/docs/` (App Router docs under `01-app/`) before using any API. Notable settings in `next.config.ts`:

- `cacheComponents: true` + `partialPrefetching: true` — data fetching is dynamic by default; opt into caching with the `use cache` directive, `cacheLife`, and `cacheTag`. Route segment `runtime` exports (including `'edge'`) are not supported. For auth patterns under this model, read `01-app/02-guides/authentication-with-cache-components.md`.
- `experimental.agentFeedback: true` — `next dev` regenerates the block in `AGENTS.md`; don't hand-edit that block.
- Tailwind CSS v4 is wired through a Turbopack CSS loader rule (`@tailwindcss/turbopack`), not PostCSS. There is no `tailwind.config` — theme tokens live in `app/globals.css` (`@theme inline` + CSS variables, dark mode via the `.dark` class variant).
- Layouts/pages use the global, generated `LayoutProps<"/">` / `PageProps<...>` route types.

## UI conventions

- shadcn/ui with the `base-nova` style: primitives come from **Base UI** (`@base-ui/react`), not Radix. Components in `components/ui/` wrap Base UI primitives, use `cva` for variants, and set a `data-slot` attribute.
- `cn` comes from the `cn` npm package (re-exported by `lib/utils.ts`), not the usual `clsx` + `tailwind-merge` helper.
- Icons: `lucide-react`. Path alias `@/*` maps to the repo root (`@/components`, `@/lib`, `@/components/ui`, `@/hooks`).
