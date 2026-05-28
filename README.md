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

Admin is not a separate product. The Admin Page and Admin API are Gateway
capabilities.

## Agent-Q Gateway

Agent-Q Gateway is distributed as an npm package.

It runs locally through `npx`, exposes an MCP server for agents, serves the
Admin Page, and communicates with Agent-Q Firmware over a supported transport.

Gateway does not store keys and does not make signing or policy decisions.

## Agent-Q Firmware

Agent-Q Firmware is installed on hardware.

Firmware stores keys and policies, evaluates signing requests, handles physical
approval, and returns signatures or rejections to Gateway.

Firmware source is organized by hardware under `products/firmware/src/`.

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
third_party/
```

`.WORK/` is for local planning, scratch files, and investigation materials. It is
not tracked by Git.
