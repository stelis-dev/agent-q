# Agent-Q zkLogin Test Web App

This private app is a browser test tool for the Agent-Q Sui zkLogin setup path.
It is not production onboarding, not an Admin Page, and not a signing authority.
It is buildable test tooling only. `docs/IMPLEMENTATION_STATUS.md` is the status
source for browser-to-device zkLogin setup, clear, reconnect, and signing.

The app uses the Agent-Q Sui browser provider over Web Serial and only exercises
the common operations already exposed through that provider:

- `connect`
- `get_capabilities`
- `get_accounts`
- `credential_prepare`
- `credential_propose`
- `sign_transaction`
- `disconnect`

It does not add host-process routes, provider management APIs, signer selection,
or a proof-clear API. If zkLogin proof material already exists, clear it locally
on the device through `Settings > Sui`.

## Run

```sh
npm --workspace @stelis/agent-q-zklogin-test-web run dev
```

For Enoki-backed testing, copy `.env.example` to `.env.local` and set an Enoki
public API key. Vite exposes `VITE_*` values to browser code, so do not put
private API keys, OAuth client secrets, JWTs, salts, or signing material in the
environment file.

The default test flow is:

```text
connect Agent-Q provider
-> load Enoki app metadata
-> prepare an Enoki nonce with the device preparation public key
-> complete OAuth login
-> create an Enoki proof in the browser
-> submit only the bounded proof proposal through the Agent-Q provider
-> reconnect and read the active account
-> request a sign-only test transaction through sign_transaction
```

The Enoki path supports `mainnet`, `testnet`, and `devnet`. It rejects
`localnet` before calling Enoki. The manual path remains available for a custom
salt server or prover and ends at the same `credential_propose` provider call.

Address continuity for the Enoki path depends on the Enoki app, OAuth client
ID, issuer, and subject continuity. Agent-Q does not receive Enoki API keys,
JWTs, OAuth tokens, salts, or Enoki session state.

## Build

```sh
npm run build:zklogin-test-web
```

The transaction test builds transaction bytes for the active account, sends them
through `sign_transaction`, and does not submit or execute the transaction on a
Sui network.
