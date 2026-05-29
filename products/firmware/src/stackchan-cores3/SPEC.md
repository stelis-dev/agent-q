# StackChan CoreS3 Agent-Q Firmware Specification

This document describes the StackChan CoreS3 Agent-Q firmware target. It is the
target-specific detail document referenced by the project-wide implementation
status table.

The common Gateway/Firmware protocol is defined in `specs/PROTOCOL.md`. This
target must fit that protocol and must not define StackChan-specific product
APIs.

## Target Role

StackChan CoreS3 is the first implemented Agent-Q firmware target.

Its current role is:

- expose the implemented USB JSONL protocol requests;
- keep a persistent protocol `deviceId`;
- show temporary identification, approval, and result UI on top of the default
  StackChan avatar face;
- provide hardware smoke coverage for future signing flows.

It is not the signing product yet. It does not persist signing keys, store
policy, parse signable transactions, expose MCP directly, or sign user requests.

## Target Status

Legend:

- `O`: implemented and verified on this target.
- `△`: partially implemented or diagnostic-only.
- `X`: not implemented.
- `N/A`: not applicable to this target.

| Capability | Status | Notes |
|---|---:|---|
| USB JSONL transport | O | Uses ESP32-S3 USB Serial/JTAG. |
| Persistent protocol `deviceId` | O | Stored in NVS namespace `agent_q`, key `device_id`. |
| `get_status` | O | Returns device id and current state without approval UI. |
| `identify_device` | O | Shows a short code using temporary Agent-Q avatar UI. |
| `display_signal` diagnostic | O | Shows a decision UI and returns after touch approval, rejection, or timeout. |
| `connect` | O | Requires touch approval and returns a Firmware-generated runtime session id. |
| `disconnect` | O | Clears the active session when the supplied session id matches. |
| Runtime session storage | O | RAM only; reboot clears the session. |
| Agent-Q avatar UI | O | Uses an Agent-Q-owned speech-bubble decorator and top decision strip. |
| Result feedback UI | O | Shows temporary result speech and returns to the default avatar. |
| Head movement feedback | O | Briefly raises the head for notification, approval, and success states. |
| Ed25519 signing self-test | △ | Runtime-generated test seed only; wiped after the self-test. Not a signing API. |
| `get_capabilities` | X | Not implemented. |
| `get_accounts` | X | Not implemented. |
| `call_method` | X | Not implemented. |
| Persistent signing keys | X | Not implemented. |
| Provisioning flow | X | Not implemented. The target has display/touch hardware suitable for a future local backup-confirmation flow. |
| Policy storage/evaluation | X | Not implemented. |
| Secure user profile | X | Not implemented. |

## Chain And Method Support

This target currently has no user-facing chain signing API. The only chain code
present is a Sui Ed25519 boot-time self-test that uses a runtime-generated test
seed, verifies the result locally, and wipes the test seed.

| Chain / method | Status | Notes |
|---|---:|---|
| Sui Ed25519 self-test | △ | Diagnostic only. It proves the signing dependency links and works on-device. |
| Sui `sign_personal_message` | X | Not implemented. |
| Sui `sign_transaction` | X | Not implemented. |
| Sui txBytes decoding | X | Not implemented. |
| Sui zkLogin | X | Not implemented; requires a separate trust model. |
| EVM signing | X | Not implemented. |
| Solana signing | X | Not implemented. |

Future chain support must be exposed through the common session-scoped protocol
flow: `connect -> get_capabilities -> get_accounts -> call_method* ->
disconnect`. This target must not add StackChan-specific or chain-specific MCP
tools.

## StackChan Runtime Boundary

Agent-Q uses StackChan CoreS3 as an avatar-based approval surface, not as a
general StackChan AI firmware.

The Agent-Q build keeps:

- the local launcher;
- the local default avatar idle surface;
- the USB Agent-Q request server;
- local touch and motion feedback needed for Agent-Q UI.

The Agent-Q build disables or avoids:

- StackChan/Xiaozhi remote AI runtime;
- StackChan World login;
- Xiaozhi remote MCP tools;
- camera initialization;
- setup/login worker;
- remote avatar WebSocket service;
- camera, screen snapshot, and remote video upload surfaces.

Developers who need upstream StackChan AI/cloud features should flash upstream
StackChan firmware separately and must not treat that firmware as an Agent-Q
signing device.

## UI State Model

StackChan owns the default avatar face and normal device runtime.

Agent-Q owns only the temporary UI objects it creates:

- Agent-Q speech-bubble decorator;
- top decision strip for Cancel/Confirm;
- temporary emotion override;
- temporary head movement feedback.

Agent-Q must remove only its own temporary UI. It must not force a dedicated
Agent-Q app mode for normal requests.

Current UI behavior:

| Request or state | UI behavior | Firmware state |
|---|---|---|
| `get_status` | No UI | `idle` unless approval UI is active |
| `identify_device` | Temporary speech bubble with short code | `idle` |
| `display_signal` pending | Speech bubble plus top Cancel/Confirm strip | `awaiting_approval` |
| `connect` pending | Speech bubble plus top Cancel/Confirm strip | `awaiting_approval` |
| Approved result | Temporary success speech and emotion | `idle` |
| Rejected result | Temporary rejected speech and emotion | `idle` |
| Timeout result | Temporary timeout speech and emotion | `idle` |

The StackChan default avatar face remains visible. Agent-Q does not use the
upstream default speech bubble at runtime; it uses the Agent-Q-owned speech
bubble decorator so request UI ownership is explicit.

## Session Model

`connect` creates one active Firmware runtime session after physical approval.
The session id is generated by Firmware and held in RAM. A new approved
`connect` replaces the previous Firmware session.

`disconnect` clears the session only when the supplied session id matches the
active Firmware session.

Sessions do not authorize signing. They only establish a communication session
for future session-scoped protocol requests.

## Persistent Storage

This target currently persists only the protocol `deviceId`.

| Namespace | Key | Purpose |
|---|---|---|
| `agent_q` | `device_id` | Gateway reconnect and device-selection identity |

Agent-Q-owned modules are sources under `agent_q/` in this target tree. These
modules may share the `agent_q` namespace. New keys should be named by feature,
such as `<feature>_<name>`, to avoid collisions.

## Provisioning Capability

Provisioning is not implemented on this target.

StackChan CoreS3 has a display and touch input, so it is a candidate for a
future local provisioning flow:

- generate a new mnemonic on the device;
- show the mnemonic on the device once for backup;
- require local confirmation before storing it;
- accept imported mnemonic input only through an explicitly weaker setup path;
- expose only public keys and addresses after provisioning.

Until that exists, this target must not be described as holding persistent user
signing material.

## Build Inputs

This directory is an overlay for the pinned upstream StackChan firmware host.
It is not a standalone ESP-IDF project.

Pins:

- target host firmware pin: `products/firmware/src/stackchan-cores3/source.env`;
- shared firmware dependency pins: `products/firmware/source.env`.

Tracked helper scripts fetch pinned inputs into `.firmware-cache/`, apply the
Agent-Q overlay, and build. The build must not depend on `.WORK/`.

## Verification

Current verification expectations for this target:

- build with `tools/firmware/stackchan-cores3/build.sh` after ESP-IDF v5.5.4 is
  active;
- flash to a StackChan CoreS3 device when hardware is available;
- smoke-test `get_status`;
- smoke-test `identify_device`;
- smoke-test `display_signal` approval, rejection, and timeout behavior;
- smoke-test `connect` approval, rejection, timeout, and `disconnect`;
- visually verify that Agent-Q temporary UI does not leave the avatar in an
  Agent-Q-specific mode after completion.
