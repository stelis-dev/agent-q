# Agent-Q Core

> Development status: Agent-Q is an active development project with
> hardware-tested Sui signing paths for CLI, MCP, and supported provider flows.
> The current StackChan CoreS3 Firmware path uses DEV_PROFILE material intended
> for development and demos, not real-asset custody. See the root README
> Current Status section for storage and profile limitations.

`@stelis/agent-q-core` is the shared Agent-Q core package.

It provides transport, protocol builders and parsers, runtime session mirroring,
local device selection/config storage, public error mapping, and Firmware result
parsing. The `agent-q` local server, Sui provider, and Sui CLI signer use this
package instead of reimplementing the device/protocol boundary.

The core package is not a signing authority and is not a policy authority.
It does not store signing material, does not make signing decisions, and does
not apply policy. Agent-Q Firmware owns policy evaluation, sensitive approval,
and active policy commits, and holds signing material for the implemented
material profile.

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
  -> credentialPrepare? / credentialPropose? for Sui zkLogin setup
  -> signTransaction or signPersonalMessage
  -> disconnectDevice
```

Use `getCapabilities` before signing. It reports the device's current signing
mode and supported signing methods for display and request selection. The
client cannot choose the device signing mode. Sui zkLogin credential
preparation/proposal is available only when Firmware reports the credential
capability for the active native Sui identity; it is not a signer selector or a
proof-clear path.

## Entrypoints

- `@stelis/agent-q-core` exposes the full `AgentQCore`,
  `createDefaultAgentQCore`, and low-level transport classes used by the
  `agent-q` local server.
- `@stelis/agent-q-core/device` exposes the limited
  `createDefaultAgentQDeviceClient` facade for provider/app code that should not
  see policy proposal or server management methods.
- `@stelis/agent-q-core/protocol` exposes the shared protocol builders,
  parsers, constants, and response types. It does not expose payload-transfer
  wire primitives as an application API; official transports route device
  requests through `requestDevice`, which owns direct delivery, staged payload
  transfer, and retained-response recovery internally.
- `@stelis/agent-q-core/provider-protocol` exposes the browser-safe provider
  protocol projection used by official dapp-facing adapters. It includes
  provider request builders, an exact provider request serializer, provider
  response parsers, bounded response-line handling, USB identifiers, and fixed
  internal deadline constants; it does not expose retained-response recovery
  request or response types, recovery builders, Admin, policy read/update,
  approval-history, or full-protocol request serialization.
- `@stelis/agent-q-core/device-request-internal` exposes the browser-safe
  `DeviceRequest` transport helper used by official Agent-Q adapters. It is an
  internal adapter support entrypoint, not an application API.
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
  imports the full core. Firmware remains responsible for
  validating and approving sensitive writes.
- Current StackChan CoreS3 capabilities report Sui account identity and no
  delegated signing methods in `chains[].methods`. Signing availability is
  advertised through top-level `signing.authorization` and `signing.methods`,
  and the device API facade exposes `signTransaction` and
  `signPersonalMessage`. The core parser accepts Firmware-authored
  `signing outcome` values for transaction policy/user outcomes and user-mode
  personal-message outcomes. It accepts `messageBytes` only for signed
  personal-message results and rejects raw transaction bytes in signing outcomes, decoded
  internals, session ids, request ids, and secret-like fields.
- The limited device API facade also exposes `credentialPrepare` and
  `credentialPropose` for the common Sui zkLogin setup boundary. Firmware
  accepts those operations only while the native Sui identity is active and
  stores no raw JWT, OAuth token, provider secret, or signing key material.
- External inputs do not accept caller-controlled timing fields. The host process
  uses fixed internal transport budgets. Firmware-owned device-local approval
  windows remain 30 seconds; the host process waits with a non-configurable transport
  margin so a valid terminal device result can still be received at the end of
  that window.
- Shared signing calls classify bounded `(type, chain, method)` routes before
  resolving state/session. Sui is currently the only executable chain.
  Method-parameter validation remains after a runtime session exists. Common
  Core validation owns transport bounds and canonical base64 syntax, not the
  current Sui Firmware adapter's inline, staged-payload, or decoded semantic
  capacities.

## Development

From the repository root:

```sh
npm --workspace @stelis/agent-q-core run build
npm --workspace @stelis/agent-q-core test
```

Direct USB/Firmware hardware smoke tests live in this package and are opt-in.
They are skipped unless their `AGENTQ_HW_CLIENT_*` environment gates are set.

Run one smoke scenario at a time against a development device running the
current firmware build. The device must be provisioned, connected over USB, and
already in the signing mode required by the selected gate. Use the matching
`*_DEVICE_ID` variable when more than one Agent-Q device is connected. For
transaction-signing smoke, pass canonical base64 `txBytes` whose sender and gas
owner are the Agent-Q account. For policy-mode smoke, configure the active
device policy before running the scenario.

Examples:

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
