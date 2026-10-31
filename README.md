# Auth MFE

An authentication micro-frontend that a chatbot embeds in an iframe, with its own BFF that talks to the in-house IdP. After sign-in, the BFF sets a short-lived, IdP-signed `auth_token` cookie on the shared root domain, and the chatbot's backend verifies it. See [docs/auth-flow.md](docs/auth-flow.md) for the full flow.

## Layout

- `apps/auth-mfe`: the auth MFE and its BFF (Next.js). The only deployable.
- `apps/mock-idp`: local mock of the in-house IdP.
- `apps/chatbot-host`: reference chatbot that embeds the MFE and verifies the cookie.
- `packages/sdk`: `@auth-mfe/sdk`, the chatbot-side SDK and postMessage protocol.
- `packages/token-verifier`: `@auth-mfe/token-verifier`, the `auth_token` check for chatbot backends.
- `packages/idp-contract`: the IdP API contract, shared by the BFF and the mock.
- `packages/dev-certs`, `packages/tsconfig`, `packages/eslint-config`: dev tooling.

## Getting started

Requires Node 22.12+ and pnpm 12.

```bash
pnpm install
cp apps/auth-mfe/.env.example apps/auth-mfe/.env.local
pnpm dev
```

`pnpm dev` opens Turborepo's terminal UI with one log pane per app: pick a pane with `↑`/`↓` (`m` lists the keys, `Ctrl+C` stops everything). To keep each app in its own terminal instead, run `pnpm dev:auth`, `pnpm dev:idp` and `pnpm dev:chat` separately.

Then open https://chat.localtest.me:4000 and sign in as `alice@example.com` / `password123`. The emailed one-time code is printed in the mock IdP's pane (`@auth-mfe/mock-idp`).

`pnpm build`, `pnpm lint`, `pnpm typecheck` and `pnpm test` run across the workspace through Turborepo.
