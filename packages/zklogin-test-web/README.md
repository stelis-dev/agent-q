# Agent-Q zkLogin Test Web App

This private app is a browser test tool for the Agent-Q Sui zkLogin setup path.
It is not production onboarding, not an Admin Page, and not a signing authority.

The app talks directly to Firmware over Web Serial and only uses the common
protocol operations already exposed by Agent-Q:

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
