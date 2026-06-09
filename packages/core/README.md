# Agent-Q Core

`@stelis/agent-q-core` is the shared Agent-Q core package.

It provides transport, protocol builders and parsers, runtime session mirroring,
local device selection/config storage, public error mapping, and Firmware result
parsing. The `agent-q` local server, Sui provider, and Sui CLI signer use this
package instead of reimplementing the device/protocol boundary.

The core package is not a signing authority and is not a policy authority.
It does not store signing keys, does not make signing decisions, and does not
apply policy. Agent-Q Firmware owns keys, policy evaluation, sensitive approval,
and active policy commits.

## Quick Start

Use this package directly when a Node process needs to discover an Agent-Q
device, open a session, read accounts, and request signatures.

```ts
import { createDefaultAgentQDeviceClient } from "@stelis/agent-q-core/device";

const client = createDefaultAgentQDeviceClient();

await client.scanDevices();
await client.connectDevice({});

const accounts = await client.getAccounts({});

const result = await client.signTransaction({
  chain: "sui",
  method: "sign_transaction",
  network: "testnet",
  txBytes,
});

await client.disconnectDevice({});
```

The core request succeeds only when Firmware accepts the state, session,
route, parameters, policy or device-confirmation gate, and signing operation.

## Common Flow

```text
scanDevices
  -> identifyDevices?
  -> selectDevice?
  -> connectDevice
  -> getCapabilities
  -> getAccounts
  -> signTransaction or signPersonalMessage
  -> disconnectDevice
```

Use `getCapabilities` before signing. It reports the device's current signing
mode and supported signing methods for display and request selection. The
client cannot choose the device signing mode.

## Entrypoints

- `@stelis/agent-q-core` exposes the full `AgentQCore`,
  `createDefaultAgentQCore`, and low-level transport classes used by the
  `agent-q` local server.
- `@stelis/agent-q-core/device` exposes the limited
  `createDefaultAgentQDeviceClient` facade for provider/app code that should not
  see policy proposal or server management methods.
- `@stelis/agent-q-core/protocol` exposes the shared protocol builders,
  parsers, constants, and response types.
- `@stelis/agent-q-core/provider-protocol` exposes the browser-safe provider
  protocol projection used by official dapp-facing adapters. It includes
  provider request builders, an exact provider request serializer, provider
  response parsers, bounded response-line handling, USB identifiers, and fixed
  internal deadline constants; it does not expose Admin, policy read/update,
  approval-history, or full-protocol request serialization.
- `@stelis/agent-q-core/adapter-internal` exposes support APIs for official
  Agent-Q adapters, including bounded output schemas, public error mapping, safe
  text validation, and the local host device registry. It is not the
  dapp-facing provider API.

## Boundaries

- A connection session opens a communication channel between the host process and
  Firmware. It is not signing approval.
- Session ids are held in host process memory only and are not returned to callers.
- Labels and purpose names are local host process metadata. They are not Firmware
  policy and are not authorization facts.
- Policy update proposals are available only through the full core. They are
  not part of the limited device API facade.
  This is API surface separation, not a security barrier against code that
  deliberately imports the full core. Firmware remains responsible for
  validating and approving sensitive writes.
- Current StackChan CoreS3 capabilities report Sui account identity and no
  delegated signing methods in `chains[].methods`. Signing availability is
  advertised through top-level `signing.authorization` and `signing.methods`,
  and the device API facade exposes `signTransaction` and
  `signPersonalMessage`. The core parser accepts Firmware-authored
  `sign_result` values for transaction policy/user outcomes and user-mode
  personal-message outcomes. It accepts `messageBytes` only for signed
  personal-message results and rejects raw transaction bytes in results, decoded
  internals, session ids, request ids, and secret-like fields.
- External inputs do not accept caller-controlled timing fields. The host process
  uses fixed internal transport budgets. Firmware-owned device-local approval
  windows remain 30 seconds; the host process waits with a non-configurable transport
  margin so a valid terminal device result can still be received at the end of
  that window.
- Shared signing calls classify bounded `(type, chain, method)` routes before
  resolving state/session. Sui is currently the only executable chain.
  Method-parameter validation remains after a runtime session exists. Common
  Core validation owns transport bounds and canonical base64 syntax, not the
  current Sui Firmware adapter's decoded-payload capacities.

## Development

From the repository root:

```sh
npm --workspace @stelis/agent-q-core run build
npm --workspace @stelis/agent-q-core test
```

Direct USB/Firmware hardware smoke tests live in this package and are opt-in.
They are skipped unless their `AGENTQ_HW_CLIENT_*` environment gates are set:

```sh
npm --workspace @stelis/agent-q-core run build

AGENTQ_HW_CLIENT_SIGN_TRANSACTION_USER=1 \
AGENTQ_HW_CLIENT_SIGN_TRANSACTION_USER_SCENARIO=positive \
AGENTQ_HW_CLIENT_SIGN_TRANSACTION_USER_TX_BYTES=<base64> \
node --test packages/core/test/hardware-sign-api-smoke.test.mjs

AGENTQ_HW_CLIENT_SIGN_TRANSACTION_POLICY=1 \
AGENTQ_HW_CLIENT_SIGN_TRANSACTION_POLICY_SCENARIO=rejected \
node --test packages/core/test/hardware-sign-api-smoke.test.mjs

AGENTQ_HW_CLIENT_POLICY_UPDATE=1 \
node --test packages/core/test/hardware-sign-api-smoke.test.mjs
```

Adapter packages keep their tests focused on adapter projection and public API
boundaries. Hardware smoke evidence must still record target hardware, commit,
build/flash command, manual steps, observed result, and unchecked paths before
implementation status is raised.
