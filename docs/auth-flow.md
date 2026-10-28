# Auth MFE: end-to-end flow

How a chatbot user signs in through the embedded auth MFE, and how the chatbot ends up with its own session.

- **Chatbot UI** embeds the MFE with `openAuthMfe()` from `packages/chatbot-sdk`.
- **Auth MFE iframe** is `/login` or `/register` from `app/(auth)/`.
- **Auth BFF** is this Next.js app's server side: Server Actions, `proxy.ts` and `/api/handoff/*`.
- **Chatbot backend** redeems the one-time code server-to-server. See `examples/chatbot-host/` for a reference implementation.

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant CU as Chatbot UI<br/>(chat.example.com)
    participant CB as Chatbot backend
    participant IF as Auth MFE iframe<br/>(auth.example.com)
    participant BFF as Auth BFF<br/>(Next.js server)
    participant IdP as In-house IdP

    CU->>CB: GET /api/me
    CB-->>CU: 401 (not signed in)
    CU-->>U: Show "Login" button

    U->>CU: Click Login
    Note over CU: SDK openAuthMfe():<br/>random nonce (256-bit)
    CU->>IF: Insert sandboxed iframe<br/>/login?parent=chat-origin&nonce=N
    IF->>BFF: GET /login?parent=…&nonce=…
    Note over BFF: proxy.ts: CSP frame-ancestors = allowlist<br/>EmbedGate: parent in allowlist? nonce valid?
    BFF-->>IF: Login form (parent origin + nonce)
    IF-->>CU: postMessage auth:ready / auth:resize<br/>(targetOrigin = parent)
    Note over CU: SDK checks origin, source = iframe, nonce

    U->>IF: Enter email + password, submit
    IF->>BFF: Server Action loginAction(formData)
    Note over BFF: Origin == Host check (Next.js)<br/>re-check parent vs allowlist<br/>validate input (zod)<br/>rate limit per IP + per email
    BFF->>IdP: POST /api/login (Basic client auth)

    alt Wrong credentials / locked / IdP down
        IdP-->>BFF: 401 / 423 / 5xx
        BFF-->>IF: { status: error, message }
        IF-->>U: Show error (generic for bad credentials)
    else Valid credentials
        IdP-->>BFF: access, refresh and ID tokens
        Note over BFF: Verify ID token (JWKS, iss, aud)<br/>Create session (tokens stay server-side)<br/>Mint one-time code: hashed, 60 s,<br/>bound to session + parent origin
        BFF-->>IF: Set-Cookie __Host-auth_session (HttpOnly, Secure, Lax)<br/>{ status: success, code }
        IF-->>U: "Signed in as … Returning to the chat…"
        IF-->>CU: postMessage auth:success { code, nonce }<br/>(targetOrigin = parent)
        Note over CU: SDK checks origin, source, nonce<br/>removes iframe, resolves { code }

        CU->>CB: POST /api/session { code }
        Note over CB: Origin == chat origin (CSRF)
        CB->>BFF: POST /api/handoff/exchange { code, parent_origin }<br/>(Basic: HANDOFF_CLIENT_ID / SECRET)
        Note over BFF: Check client creds<br/>take code (single use)<br/>parent_origin matches? session still active?

        alt Code replayed / expired / wrong origin
            BFF-->>CB: 400 invalid_grant
            CB-->>CU: 401 login_failed
        else Code valid
            BFF-->>CB: { user, session_ref, session_expires_at }<br/>(no IdP tokens)
            Note over CB: Create own session
            CB-->>CU: Set-Cookie chat_session (HttpOnly, Secure, Lax)<br/>{ user }
            CU-->>U: Signed in as Alice
        end
    end

    opt Logout
        U->>CU: Click Log out
        CU->>CB: POST /api/logout
        CB->>BFF: POST /api/handoff/logout { session_ref } (Basic)
        BFF->>IdP: POST /api/logout { refresh_token }
        BFF-->>CB: 204
        CB-->>CU: 204 + clear chat_session
    end
```

## Not shown

- **Cancel:** the Cancel button inside the MFE sends `auth:cancel`. The SDK then removes the iframe and resolves `{ status: "cancelled" }`.
- **Timeout:** if `auth:ready` doesn't arrive within 15 s (the `readyTimeoutMs` option), the SDK throws `AuthMfeError("timeout")`. This is what happens when the chatbot's origin isn't allowed to frame the page.
- **Register:** works the same way as login, through `registerAction` and the IdP's `POST /api/register`. Its rate limit is per IP only.
- **Token refresh:** the auth BFF can refresh an access token that is about to expire through the IdP (`getActiveSession` in `lib/session.ts`). Nothing calls this yet.
