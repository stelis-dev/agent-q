# Agent-Q

Agent-Q separates agent execution from signing authority.

Agents send signing requests through Agent-Q Gateway. A separate Agent-Q device
stores keys and policies locally, evaluates each request against those policies,
and decides whether to sign automatically, ask for physical approval, or reject
it.

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

Admin is not a separate product. The Admin Page and Admin API are intended
Gateway capabilities, not yet implemented (see Current Status below).

## Agent-Q Gateway

Agent-Q Gateway is distributed as an npm package.

It runs locally through `npx`, exposes an MCP server for agents, and
communicates with Agent-Q Firmware over a supported transport.

Gateway does not store keys and does not make signing or policy decisions.

## Agent-Q Firmware

Agent-Q Firmware is installed on hardware.

Firmware stores keys and policies, evaluates signing requests, handles physical
approval, and returns signatures or rejections to Gateway.

Firmware source is organized by hardware under `products/firmware/src/`.

Firmware builds must not depend on `.WORK/`. Shared firmware dependency pins
live in `products/firmware/source.env`; hardware-specific host firmware pins
live under `products/firmware/src/<hardware-id>/source.env`. Tracked tools fetch
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
- Connection sessions. A `connect_device` call requests physical approval on
  Firmware, and an approved session is held in Gateway memory only.
- Disconnect.
- Read-only Sui account and public-key discovery over an approved runtime
  session.
- A session-scoped `call_method` runtime skeleton that currently rejects every
  method as unsupported. It is not signing support.
- A common host-tested policy evaluator and default-reject runtime boundary that
  are not connected to runtime signing.

Not yet implemented: concrete signing methods, runtime policy enforcement or
storage, Admin Page, and chain-specific transaction logic. Connection is not
signing approval and does not authorize signing. A connection session does not
prove agent identity. Labels and purpose names are local Gateway metadata and
are not security boundaries.

## Repository Layout

```text
specs/
  PROTOCOL.md

products/
  gateway/
  firmware/
    README.md
    src/
    build/

tools/
  firmware/
    <hardware-id>/
```

`.WORK/` is for local planning, scratch files, and investigation materials. It is
not tracked by Git.

`.firmware-cache/` is for pinned firmware build dependencies downloaded by
tracked helper scripts. It is not tracked by Git.
