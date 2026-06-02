# Agent-Q Client

`@stelis/agent-q-client` is the device-facing Agent-Q client package.

It provides the Gateway core, USB transport, runtime session mirror, and
protocol builders and parsers used by Agent-Q adapters.

The client package is not a signing authority and is not a policy authority.
It does not store signing keys, does not make signing decisions, and does not
apply policy. Agent-Q Firmware owns keys, policy evaluation, sensitive approval,
and active policy commits.

## Entrypoints

- `@stelis/agent-q-client` exposes the default Gateway core factory.
- `@stelis/agent-q-client/core` exposes the core class and result types.
- `@stelis/agent-q-client/protocol` exposes the shared protocol builders,
  parsers, constants, and response types.
- `@stelis/agent-q-client/usb` exposes the USB transport boundary.
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
- `proposePolicyUpdate` submits a bounded proposal to Firmware. Firmware
  validates, requires device-local approval, commits policy, and records the
  terminal result.
- Current StackChan CoreS3 capabilities do not advertise signing methods.

## Development

From the repository root:

```sh
npm --workspace @stelis/agent-q-client run build
npm --workspace @stelis/agent-q-client test
```
