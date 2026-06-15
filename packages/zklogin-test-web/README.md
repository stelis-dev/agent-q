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

## Build

```sh
npm run build:zklogin-test-web
```

The transaction test builds transaction bytes for the active account, sends them
through `sign_transaction`, and does not submit or execute the transaction on a
Sui network.
