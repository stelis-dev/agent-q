# Agent-Q zkLogin Test Web App

> Development status: Agent-Q is an active development project with
> hardware-tested Sui signing paths for CLI, MCP, and supported provider flows.
> The current StackChan CoreS3 Firmware path uses DEV_PROFILE material intended
> for development and demos, not real-asset custody. See the root README
> Current Status section for storage and profile limitations.

This non-production app is a browser test tool for the Agent-Q Sui zkLogin setup
path. It is not production onboarding, not an Admin Page, and not a signing
authority. It is buildable test tooling only. `docs/IMPLEMENTATION_STATUS.md` is
the status source for provider/browser zkLogin setup, clear, reconnect, and
signing.

The app imports `@stelis/agent-q-provider-sui/browser`, uses the Agent-Q Sui
browser provider over Web Serial, and only exercises the common operations
already exposed through that provider:

- `connect`
- `get_capabilities`
- `get_accounts`
- `credential_prepare`
- `credential_propose`
- `sign_transaction`
- `disconnect`

It does not add host-process routes, provider management APIs, signer selection,
or a proof-clear API. If zkLogin proof material already exists, clear it locally
on the device through `Settings > Accounts > Sui`.

## Run

```sh
npm --workspace @stelis/sample-zklogin-test-web run dev
```

For Enoki-backed testing, copy `.env.example` to `.env.local` and set an Enoki
public API key. Vite exposes `VITE_*` values to browser code, so do not put
private API keys, OAuth client secrets, JWTs, salts, or signing material in the
environment file.
Local `.env*` files are ignored except tracked examples. Vite build output under
`dist/` is also ignored and contains the public `VITE_*` identifiers embedded in
client assets, so do not share local build artifacts as evidence that no local
configuration values exist.

This sample uses Google OAuth only. Google login requires a callback URL
registered with the Google OAuth client and the Enoki app metadata for that
client. The sample includes
`callback.html` for this purpose. Set `VITE_ZKLOGIN_REDIRECT_URI` to that
callback URL, or leave it unset to use the bundled callback page on the browser
origin printed by Vite, such as `http://127.0.0.1:5173/callback.html`.

The default test flow is:

```text
connect device
-> set Enoki configuration for Google OAuth
-> set up zkLogin with Google
-> request a sign-only zkLogin test transaction through sign_transaction
```

The page uses Sui `testnet` for Enoki nonce creation, proof proposal, and the
transaction signing test. The browser stores pending public Enoki configuration
and nonce preparation material in `sessionStorage` only until the OAuth callback
is handled. JWTs and proof JSON still pass through the browser process and
network requests during the test flow, but the page does not display them, keep
them in React state, or write them to browser storage.

Address continuity for the Enoki path depends on the Enoki app, OAuth client
ID, issuer, and subject continuity. The Agent-Q provider and device proof
proposal receive only the bounded zkLogin proof fields, not Enoki API keys,
JWTs, OAuth tokens, salts, or Enoki session state.

## Build

```sh
npm run build:sample-zklogin-test-web
```

The transaction test is enabled only after the device returns the activated
zkLogin account. It builds transaction bytes for that account, sends them
through `sign_transaction`, and does not submit or execute the transaction on a
Sui network.
