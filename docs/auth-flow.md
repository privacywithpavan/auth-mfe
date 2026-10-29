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
        Note over BFF,IdP: Second factor first (passkey or emailed code),<br/>see "Second factor and passkeys" below
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

## Second factor and passkeys

A password login always needs a second factor. A passkey login needs none, because a passkey with user verification (biometric or PIN) is already two factors. The IdP stores passkeys and verifies every WebAuthn response; the BFF only relays them. The relying party ID is the MFE's host, never the chatbot's.

Steps after the password are tied together by an **MFA ticket** (`lib/mfa-ticket.ts`): random, hashed in the store, 5 minutes, bound to the parent origin, burned when the login completes. The iframe posts it back with each step. It isn't a cookie, because the iframe is cross-site to the chatbot, and browsers don't send `SameSite=Lax` cookies there.

```mermaid
sequenceDiagram
    autonumber
    actor U as User
    participant IF as Auth MFE iframe
    participant BFF as Auth BFF
    participant IdP as In-house IdP

    alt Password first
        IF->>BFF: loginAction(email, password)
        BFF->>IdP: POST /api/login
        IdP-->>BFF: { mfa_required, mfa_token, has_passkey }
        alt Has a passkey
            BFF->>IdP: POST /api/passkeys/authentication/options { mfa_token }
            BFF-->>IF: second_factor (passkey) + ticket + options
            U->>IF: Use passkey → navigator.credentials.get()
            IF->>BFF: loginAction(intent=passkey, ticket, response)
            BFF->>IdP: POST /api/passkeys/authentication/verify
        else No passkey, or "Email me a code instead"
            BFF->>IdP: POST /api/mfa/otp/send
            BFF-->>IF: second_factor (otp) + ticket
            U->>IF: Enter 6-digit code
            IF->>BFF: loginAction(intent=verify_otp, ticket, code)
            BFF->>IdP: POST /api/mfa/otp/verify
            Note over IdP: The code also unlocks passkey creation,<br/>so a stolen password can't enroll one
            BFF->>IdP: POST /api/passkeys/registration/options
            BFF-->>IF: enroll + options
            opt Create a passkey
                U->>IF: navigator.credentials.create()
                IF->>BFF: loginAction(intent=enroll, ticket, response)
                BFF->>IdP: POST /api/passkeys/registration/verify
            end
        end
    else Passkey first
        Note over IF: On load: passkeyChallengeAction(parent)
        BFF->>IdP: POST /api/passkeys/authentication/options {}
        BFF-->>IF: ticket + options (discoverable credentials)
        Note over IF: Where supported, starts navigator.credentials.get()<br/>with mediation: conditional (passkey autofill)
        alt Autofill
            U->>IF: Pick a passkey from the email field's suggestions
        else Button
            U->>IF: Sign in with a passkey → navigator.credentials.get()<br/>(cancels the autofill request)
        end
        IF->>BFF: loginAction(intent=passkey, ticket, response)
        BFF->>IdP: POST /api/passkeys/authentication/verify
    end
    IdP-->>BFF: tokens
    Note over BFF: Burn ticket, create session,<br/>mint handoff code (as above)
```

Constraints to keep in mind:

- **Iframe delegation:** the embedding page must allow WebAuthn in the iframe (`allow="publickey-credentials-get; publickey-credentials-create"`). `openAuthMfe` does this since SDK 0.2.0. Creating passkeys in a cross-origin iframe is newer than using them, so older browsers may refuse. The UI then shows the error, and the user can choose "Not now".
- **User activation:** browsers only run WebAuthn right after a click. Options are fetched before the click (on load, or in the previous step's response), never inside it. Passkey autofill is the exception: it runs without a click.
- **Autofill:** the email field has `autocomplete="username webauthn"`. Saved passwords and saved passkeys then appear in the same suggestion list. Passwords are saved under the MFE's origin, so every chatbot that embeds it shares them.
  - **Passkey suggestions:** `PasskeySignIn` in `app/(auth)/login/passkey-steps.tsx` reuses the passkey-first challenge for a background autofill request. Picking a passkey from the suggestions signs in the same way as the button.
  - **Inside the iframe:** browsers usually wait until the user taps the field before suggesting a saved password. Passkey autofill works in local testing. Support in cross-origin iframes isn't documented across browsers, so "Sign in with a passkey" stays as the entry point that always works.
  - **After a cancelled prompt:** if the user dismisses the button's passkey prompt, passkeys drop out of the suggestions until the next server response brings a fresh challenge.
- **RP ID:** changing it later orphans every passkey. Pick the MFE host or its registrable domain before launch.

## Not shown

- **Cancel:** the Cancel button inside the MFE sends `auth:cancel`. The SDK then removes the iframe and resolves `{ status: "cancelled" }`.
- **Timeout:** if `auth:ready` doesn't arrive within 15 s (the `readyTimeoutMs` option), the SDK throws `AuthMfeError("timeout")`. This is what happens when the chatbot's origin isn't allowed to frame the page.
- **Register:** works the same way as login, through `registerAction` and the IdP's `POST /api/register`. Its rate limit is per IP only. Sign-up doesn't ask for a second factor; the first password login afterwards does, and offers to create a passkey.
- **Token refresh:** the auth BFF can refresh an access token that is about to expire through the IdP (`getActiveSession` in `lib/session.ts`). Nothing calls this yet.
