# Agent-Q

Agent-Q is a device-based policy wallet for AI agents.

It focuses on delegated role authority: keeping keys, policies, and approval
decisions outside the agent runtime.

Agents can request actions, but role authority lives on separate Agent-Q
devices. Each device is designed to evaluate requests locally and, according to
its implemented capabilities and policy, reject or sign where supported.

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
request contents against local policy and limits risk through rules such as
allowlists, spending limits, rate limits, physical approval, and rejection.

## Products

Agent-Q has two deployable products:

- Agent-Q Gateway
- Agent-Q Firmware

## Agent-Q Gateway

Agent-Q Gateway is distributed as npm packages.

`@stelis/agent-q-client` provides the device-facing client layer: local device
registry, USB transport, runtime session mirror, and protocol parsing and
building. `@stelis/agent-q-mcp` provides the stdio MCP server, CLI binary, and
local Admin Page. `@stelis/agent-q-provider` provides an application-facing
adapter for current device, session, and read-only capabilities.

Gateway does not store keys and does not make signing or policy decisions. It
may relay requests, validate protocol shapes, and display summaries, but
Firmware owns the device-authorized policy boundary.

## Agent-Q Firmware

Agent-Q Firmware is installed on hardware.

Firmware is the authority component: it stores device-held key material and
policies, evaluates requests locally, handles physical approval, and returns
Firmware-authored results to Gateway. Current public signing methods are not
available.

Firmware source is organized by hardware under `firmware/src/`.

Firmware builds must not depend on `.WORK/`. Shared firmware dependency pins
live in `firmware/source.env`; hardware-specific host firmware pins
live under `firmware/src/<hardware-id>/source.env`. Tracked tools fetch
those pinned sources into the ignored `.firmware-cache/` directory, apply the
tracked Agent-Q overlay, and build.

## Protocol

Gateway and Firmware communicate through the shared protocol in
`specs/PROTOCOL.md`.

The protocol has a clear session flow:

```text
get_status
  -> identify_device?
  -> connect
    -> get_capabilities
    -> get_accounts
    -> get_policy
    -> get_approval_history
    -> call_method*
  -> disconnect
```

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
  currently implemented device metadata, method-decision records, and
  policy-update terminal records.
- A session-scoped `call_method` path. Unknown methods reject. The current Sui
  `sign_transaction` path validates bounded restricted-transfer inputs and
  returns rejected method results; it does not expose public signing support.
- A bounded policy-update proposal path for currently enforceable reject
  policies. Gateway/MCP can submit proposals, but Firmware validates them,
  requires device-local approval, commits the active policy, and records the
  terminal result.
- A local Gateway-served Admin Page for device discovery, connection, policy
  summary, approval history, and the current reject-policy proposal template. It
  is not a policy authority.
- An application-facing provider package for device discovery, connection,
  read-only session data, and approval-history. The provider does not store
  keys, update policy, or decide whether signing is allowed.
- A common host-tested policy evaluator and default-reject runtime boundary.

Not yet implemented: public signing methods, automatic signing policies,
arbitrary Sui transaction signing, Sui personal-message signing,
spending and rate limits beyond the current restricted-transfer criteria,
multi-role separation, full Admin policy editing, multi-device approval, device
revocation or transfer, a production audit layer beyond the current fixed-size
approval-history record, and broad chain-specific transaction logic. Connection
is not signing approval and does not authorize signing. A connection session
does not prove agent identity. Labels and purpose names are local Gateway
metadata and are not security boundaries. Firmware policy must not rely on
Gateway labels, purpose names, or routing assignments as authorization facts.

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
  provider/

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
