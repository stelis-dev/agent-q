# Agent-Q Client

`@stelis/agent-q-client` is the device-facing Agent-Q client package.

It provides the device client facade, USB transport, runtime session mirror,
and protocol builders and parsers used by Agent-Q adapters.

The client package is not a signing authority and is not a policy authority.
It does not store signing keys, does not make signing decisions, and does not
apply policy. Agent-Q Firmware owns keys, policy evaluation, sensitive approval,
and active policy commits.

## Entrypoints

- `@stelis/agent-q-client` exposes the admin-disabled device client factory and
  device-facing result types.
- `@stelis/agent-q-client/admin` exposes the admin-capable Gateway core for MCP
  and the local Admin Page.
- `@stelis/agent-q-client/protocol` exposes the shared protocol builders,
  parsers, constants, and response types.
- `@stelis/agent-q-client/adapter-internal` exposes support APIs for official
  Agent-Q adapters, including bounded output schemas, public error mapping, safe
  text validation, and the local Gateway device registry. It is not the
  dapp-facing provider API.

## Boundaries

- A connection session opens a communication channel between Gateway and
  Firmware. It is not signing approval.
- Session ids are held in Gateway memory only and are not returned to callers.
- Labels and purpose names are local Gateway metadata. They are not Firmware
  policy and are not authorization facts.
- Policy update proposals are available only through the explicit admin-capable
  entrypoint. They are not part of the admin-disabled device client facade.
  This is API surface separation, not a security barrier against code that
  deliberately imports the admin entrypoint. Firmware remains responsible for
  validating and approving sensitive writes.
- Current StackChan CoreS3 capabilities report Sui account identity and no
  delegated signing methods in `chains[].methods`. Provider-facing
  device-confirmed signing availability is advertised through top-level
  `signing`, and the device client facade exposes `signByUser`
  for the provider-facing path. The client parser accepts `sign_result` for
  both `signByUser` and `signByPolicy`, then enforces the expected
  authorization source at the Gateway core boundary. It rejects
  raw transaction bytes in results, decoded internals, session ids, request ids,
  and secret-like fields.
- External client inputs do not accept caller-controlled timing fields. Gateway
  uses fixed internal transport budgets. Firmware-owned device-local approval
  windows remain 30 seconds; Gateway waits with a non-configurable transport
  margin so a valid terminal device result can still be received at the end of
  that window.

## Development

From the repository root:

```sh
npm --workspace @stelis/agent-q-client run build
npm --workspace @stelis/agent-q-client test
```

Direct USB/Firmware hardware smoke tests live in this package and are opt-in.
They are skipped unless their `AGENTQ_HW_CLIENT_*` environment gates are set:

```sh
npm --workspace @stelis/agent-q-client run build

AGENTQ_HW_CLIENT_SIGN_BY_USER=1 \
AGENTQ_HW_CLIENT_SIGN_BY_USER_SCENARIO=positive \
AGENTQ_HW_CLIENT_SIGN_BY_USER_TX_BYTES=<base64> \
node --test packages/client/test/hardware-sign-api-smoke.test.mjs

AGENTQ_HW_CLIENT_SIGN_BY_POLICY=1 \
AGENTQ_HW_CLIENT_SIGN_BY_POLICY_SCENARIO=rejected \
node --test packages/client/test/hardware-sign-api-smoke.test.mjs

AGENTQ_HW_CLIENT_POLICY_UPDATE=1 \
node --test packages/client/test/hardware-sign-api-smoke.test.mjs
```

Adapter packages keep their tests focused on adapter projection and public API
boundaries. Hardware smoke evidence must still record target hardware, commit,
build/flash command, manual steps, observed result, and unchecked paths before
implementation status is raised.
