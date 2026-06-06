# Agent-Q

Agent-Q is a device-based policy wallet for AI agents.

It focuses on delegated role authority: keeping keys, policies, and approval
decisions outside the agent runtime.

Agents can request actions, but role authority lives on separate Agent-Q
devices. Each device is designed to evaluate requests locally and, according to
its implemented capabilities and policy, reject unsafe requests or execute
explicitly implemented signing paths.

The agent can request. The device decides.

## Philosophy

For Agent-Q, agent identity is not personality. It is the role authority an
agent is allowed to exercise. An agent's model, prompt, tools, and runtime may
change, but a role can persist: Treasury, Deployment, Procurement, Recovery, or
Personal Spending. Each role needs keys, policies, limits, approval rules, and
eventually an audit trail.

Agent-Q treats that role authority as something that should live outside the
agent runtime.

## Positioning

AI identity is a broad space. Some systems focus on agent discovery,
reputation, verification, ownership, enterprise access, or payment mandates.

Agent-Q focuses on one narrower layer: delegated role authority for signing and
policy-controlled actions.

In Agent-Q, a device represents a role. The agent can request actions under that
role, but the role's keys, policies, approval rules, and decision records stay
on or originate from the device.

Agent-Q is designed to complement the broader AI identity ecosystem by focusing
on the authority boundary: what an agent is allowed to do, under which role, and
under which device-held policy.

## Current Scope

Agent-Q does not try to cover every part of the AI identity stack today. It does
not currently provide discovery registries, reputation scoring, ownership
protocols, enterprise identity management, payment mandate infrastructure, or
runtime-risk verification.

Some of those layers may connect to Agent-Q later. Runtime-risk verification
remains outside Agent-Q's authority boundary. The current focus is
device-backed role authority: keeping keys, policies, and approval decisions
outside the agent runtime.

## Security Boundary

Agent-Q cannot observe or verify what happened inside an agent, application, or
host environment before a signing request was created.

Agent-Q does not determine whether a request reflects the user's original
intent, prompt injection, compromised agent behavior, or another upstream cause.
All external requests are treated as untrusted inputs. Firmware evaluates the
request contents against local policy and limits risk through automatic rules
such as allowlists, spending limits, rate limits, and rejection. Device-local
approval is a separate request/state gate, not a policy action or policy
escalation path.
Agent-Q distinguishes policy authorization from device-local confirmation as
separate Firmware-owned signing gates. Device confirmation is a Firmware-owned
approval step for a bounded request; it does not prove that the host, dapp,
provider, agent, or upstream user intent was trustworthy. Protocol requests and
adapter surfaces do not choose the signing authorization mode.

## Products

Agent-Q has two deployable products:

- Agent-Q Gateway
- Agent-Q Firmware

## Agent-Q Gateway

Agent-Q Gateway is distributed as npm packages.

`@stelis/agent-q-client` provides the device-facing client layer: local device
registry, USB transport, runtime session mirror, and protocol parsing and
building. `@stelis/agent-q-mcp` provides the stdio MCP server, CLI binary, and
local Admin Page. `@stelis/agent-q-provider-sui` provides the Sui
application-facing adapter for current device, session, read-only Sui
capabilities, Sui `signTransaction`, user-confirmed `signPersonalMessage`, and
an app-imported Sui Wallet Standard registration adapter for
`sui:signTransaction` and `sui:signPersonalMessage`.

Current package roles and dependencies:

| Package | Role | Depends on | Uses client how |
| --- | --- | --- | --- |
| `@stelis/agent-q-client` | Device-facing SDK for hardware discovery, USB transport, runtime sessions, protocol builders/parsers, and output schemas. | Firmware protocol / USB transport. | Owns the direct Firmware protocol boundary. |
| `@stelis/agent-q-mcp` | Local Gateway adapter: stdio MCP server, CLI binary, and local Admin Page. | `@stelis/agent-q-client`. | Uses the admin-capable client entrypoint for MCP tools and Admin Page requests. |
| `@stelis/agent-q-provider-sui` | Sui dapp-facing provider and Wallet Standard adapter for `sui:signTransaction` and `sui:signPersonalMessage`. | `@stelis/agent-q-client` and Sui SDK packages. | Uses the device client facade for dapp-facing discovery, connection, account reads, capabilities, `signTransaction`, and user-confirmed `signPersonalMessage`. |
| `packages/example-sui-dapp-kit` | Private workspace example for dapp-kit integration. | `@stelis/agent-q-provider-sui` and dapp-kit dependencies. | Uses the provider-sui Wallet Standard adapter with an injected provider runtime. |

MCP and provider packages narrow the API surface they present to their audience,
but that package-level projection is not a hard security barrier. Code running
in the same host application can deliberately import broader client entrypoints,
including `@stelis/agent-q-client/admin`. Firmware remains the authority that
enforces state gates, policy evaluation, device-local confirmation, signing,
persistence, and cleanup.

Gateway does not store keys and does not make signing or policy decisions. It
may relay requests, validate protocol shapes, and display summaries, but
Firmware owns the device-authorized policy boundary.

## Agent-Q Firmware

Agent-Q Firmware is installed on hardware.

Firmware is the authority component: it stores device-held key material and
policies, evaluates requests locally, handles device-local approval for
implemented sensitive flows, and returns Firmware-authored results to Gateway.
The current bounded Sui Sign API source surface includes `sign_transaction` for
restricted-transfer transaction bytes and user-mode-only `sign_personal_message`
for bounded personal-message bytes. Firmware reads its device-local signing
authorization mode for transaction signing, then chooses either the policy
signing gate or the user-confirmed signing gate; requests do not choose it.
Detailed hardware evidence status is tracked in `docs/IMPLEMENTATION_STATUS.md`.
The current Sign API paths remain `source-wired-not-product-active`: the full
current-tree Sign API hardware matrix and LVGL clear-signing visual evidence
remain pending, so product-active signing status is not claimed.

Firmware source is organized by hardware under `firmware/src/`.

Firmware builds must not depend on `.WORK/`. Shared firmware dependency pins
live in `firmware/source.env`; hardware-specific host firmware pins
live under `firmware/src/<hardware-id>/source.env`. Tracked tools fetch
those pinned sources into the ignored `.firmware-cache/` directory, apply the
tracked Agent-Q overlay, and build.

## Protocol

Gateway and Firmware communicate through the shared protocol in
`specs/PROTOCOL.md`.

The active-session baseline has a clear session flow:

```text
get_status
  -> identify_device?
  -> connect
    -> get_capabilities
    -> get_accounts
    -> policy_get
    -> get_approval_history
    -> sign_transaction*
    -> sign_personal_message*
  -> disconnect
```

`sign_transaction` is the shared transaction signing request. Firmware selects
the signing gate from its local signing mode: policy mode evaluates the active
policy and signs with speech-bubble status notifications when policy authorizes
the bounded request, while user mode uses device-local clear-signing
confirmation and local PIN for the bounded request. Product-active status still
requires current-tree firmware build, flash, target hardware smoke, and visual
review evidence for the same contract.
`sign_personal_message` is a user-mode-only Sui personal-message signing
request in the same active session; policy mode fails closed until a bounded
policy model for personal-message signing is designed.

Chains, transports, and hardware targets must fit this protocol instead of
creating separate product-level APIs.

Firmware request UI should preserve the device's current state. Agent-Q should
use temporary identification, approval, and result layers instead of forcing the
device into a dedicated Agent-Q mode for normal requests.

Device discovery does not silently select an active device. Gateway first finds
candidate devices, asks them to show short identification codes, and saves the
selected device only after the user chooses one.

## Current Status

Detailed implementation status lives in `docs/IMPLEMENTATION_STATUS.md`.
Provisioning and first-install signing-material setup are defined in
`docs/PROVISIONING.md`. Product states and state-gated protocol functions are
defined in `docs/STATE_MODEL.md`.

Implemented:

- Device discovery, identification, and selection over USB.
- Gateway-local device registry with human-readable labels.
- Gateway-local routing assignments by purpose name. Purpose routing is local
  Gateway metadata, not Firmware policy.
- Connection sessions. A `connect_device` call always contacts Firmware, and
  Firmware issues an approved session only after its device-local approval
  conditions pass. The approved session is held in Gateway memory only.
- Disconnect.
- Read-only Sui account and public-key discovery over an approved runtime
  session.
- Session-scoped capability, policy-summary, and approval-history reads for the
  currently implemented device metadata, signing records, and policy-update
  terminal records.
- A session-scoped `sign_transaction` path. The current Sui `sign_transaction`
  path validates bounded restricted-transfer inputs. In policy authorization
  mode it evaluates the active Firmware policy, returns `policy_rejected` when
  no bounded sign rule matches, and returns `signed` only after a
  current-schema single-recipient bounded `sign` policy rule matches. In user
  authorization mode it uses device-local clear-signing review and local PIN
  confirmation.
- A bounded policy-update proposal path for currently enforceable reject/sign
  policies. Gateway/MCP can submit proposals, but Firmware validates them,
  rejects broad, multi-rule, or multi-recipient signing policies that the
  current device-local policy review cannot show clearly, requires device-local
  approval, commits the active policy, and records the terminal result.
- A local Gateway-served Admin Page for device discovery, connection, policy
  summary, approval history, and the current policy proposal template. It
  is not a policy authority.
- A Sui application-facing provider package for device discovery, connection,
  read-only Sui account/capability data, `signTransaction` transport, and
  user-confirmed `signPersonalMessage` transport. The provider also exposes a
  Wallet Standard registration adapter for `sui:signTransaction` and
  `sui:signPersonalMessage`, plus a Web Serial browser runtime that implements
  only the injected provider contract for browser dapps. Its dapp-facing
  provider object, browser runtime, and Wallet Standard adapter do not include
  active policy summaries, approval history, policy update, policy signing, key
  storage, signing decisions, or `sui:signAndExecuteTransaction`.
  Personal-message signing is source-wired for user authorization mode only and
  fails closed in policy mode. `signTransaction` may still use Firmware policy
  authorization when the device-local signing mode is `policy`; the provider
  cannot read, set, or override that mode. This is adapter API projection, not
  a security boundary against direct imports of broader client/Admin package
  entrypoints.
- A common host-tested policy evaluator and default-reject runtime boundary.

Under current-source verification:

- `sign_transaction` has source-wired but not product-active status for the
  bounded Sui transfer shape. The current source includes validation,
  state-first ingress, policy authorization, user clear-signing review, local
  PIN confirmation, required history, signing-critical handoff, terminal
  history, `sign_result`, provider `signTransaction`, client parser/builder,
  MCP tool, and `get_capabilities.signing` metadata. Hardware evidence status
  is tracked in `docs/IMPLEMENTATION_STATUS.md`; the full current-tree hardware
  matrix and LVGL visual evidence remain pending, so product-active status is
  not claimed.
- `sign_personal_message` has source-wired but not product-active status for
  bounded Sui personal-message bytes. It uses user clear-signing review, local
  PIN confirmation, required history, the Sui PersonalMessage intent digest,
  `sign_result`, client/MCP/provider parser/API, Wallet Standard
  `sui:signPersonalMessage`, and user-mode `get_capabilities.signing`
  metadata. Policy mode is intentionally unsupported for this method until
  matching policy facts and rules are designed. Hardware evidence status is
  tracked in `docs/IMPLEMENTATION_STATUS.md`; the full current-tree hardware
  matrix and LVGL visual evidence remain pending, so product-active status is
  not claimed.

Not yet implemented: arbitrary Sui transaction signing, sponsored Sui
transaction signing, policy-authorized Sui personal-message signing, spending
and rate limits beyond the current restricted-transfer criteria, multi-role
separation, full Admin policy editing,
multi-device approval, device revocation or transfer, a production audit layer
beyond the current fixed-size approval-history record, and broad chain-specific
transaction logic. Connection is not signing approval and does not authorize
signing. A connection session does not prove agent identity. Labels and purpose
names are local Gateway metadata and are not security boundaries. Firmware
policy must not rely on Gateway labels, purpose names, or routing assignments as
authorization facts.

## Repository Layout

```text
docs/
  IMPLEMENTATION_STATUS.md
  PROVISIONING.md
  SECURITY_MODEL.md
  STATE_MODEL.md

specs/
  PROTOCOL.md

packages/
  client/
  mcp/
  provider-sui/
  example-sui-dapp-kit/

firmware/
  README.md
  src/
  tools/
    common/
    <hardware-id>/
  build/
```

`.WORK/` is for local planning, scratch files, and investigation materials. It is
not tracked by Git.

`.firmware-cache/` is for pinned firmware build dependencies downloaded by
tracked helper scripts. It is not tracked by Git.
