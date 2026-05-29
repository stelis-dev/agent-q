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
| `get_status` | O | Returns device id, current state, and provisioning status without approval UI. |
| Provisioning status reporting | △ | Reports NVS-backed `unprovisioned` or `provisioning`; hardware smoke of the NVS-backed path is still required. This is not signing readiness. |
| `start_provisioning` / `cancel_provisioning` | △ | Requires touch approval and stores only the provisioning state flag. Hardware smoke is still required. |
| `provisioning_setup_check` | △ | Source adds a handler valid only while `provisioning`; it requires touch approval and stores no signing material. Firmware build passes; hardware smoke is still required. |
| Recovery phrase setup v0 | △ | Source adds `generate_recovery_phrase` and `confirm_recovery_phrase_backup` only while `provisioning`; it generates a DEV_PROFILE BIP-39 phrase into RAM from an early-boot-seeded Agent-Q CSPRNG, displays it only on device, and wipes it on cancel/confirm/reject/display expiry/timeout. Firmware build passes; hardware smoke is still required. |
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
| Persistent signing material | X | Not implemented. |
| Mnemonic generation/import | △ | DEV_PROFILE recovery phrase generation/display source exists. Mnemonic import and USER_PROFILE persistent root storage are not implemented. |
| Provisioning flow | △ | Runtime state start/cancel and DEV_PROFILE recovery phrase display source exist. Signing material storage is not implemented. |
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
| `start_provisioning` pending | Speech bubble plus top Cancel/Confirm strip | `awaiting_approval` |
| `cancel_provisioning` pending | Speech bubble plus top Cancel/Confirm strip | `awaiting_approval` |
| `provisioning_setup_check` pending | Speech bubble plus top Cancel/Confirm strip | `awaiting_approval` |
| `generate_recovery_phrase` pending | Speech bubble plus top Cancel/Confirm strip | `awaiting_approval` |
| Recovery phrase displayed | Temporary setup panel with device-only phrase text | `busy` |
| `confirm_recovery_phrase_backup` pending | Speech bubble plus top Cancel/Confirm strip | `awaiting_approval` |
| Approved result | Temporary success speech and emotion | `idle` |
| Rejected result | Temporary rejected speech and emotion | `idle` |
| Timeout result | Temporary timeout speech and emotion | `idle` |

`idle` means no physical approval prompt or device-only setup material is
active. Recovery phrase display reports `busy` so Gateway status does not imply
that UI-replacing setup requests are available.

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

This target persists the protocol `deviceId` and the provisioning state flag.
The provisioning state flag is not signing material and does not make the
device ready to sign. Recovery phrase setup v0 stores generated phrase text only
in RAM while `provisioning`; it does not write root material, seed, account, or
policy data to NVS.

| Namespace | Key | Purpose |
|---|---|---|
| `agent_q` | `device_id` | Gateway reconnect and device-selection identity |
| `agent_q` | `prov_state` | Current provisioning state: `unprovisioned` or `provisioning` |

Agent-Q-owned modules are sources under `agent_q/` in this target tree. These
modules may share the `agent_q` namespace. New keys should be named by feature,
such as `<feature>_<name>`, to avoid collisions. ESP-IDF NVS key names are
limited to 15 characters, so this target uses `prov_state` rather than the
longer protocol field name `provisioning.state`.

## Provisioning Capability

Provisioning status reporting and runtime state start/cancel are implemented in
the target firmware code and build successfully. Hardware smoke is still
required. `get_status` returns the NVS-backed `provisioning.state`, and the USB
protocol requests `start_provisioning` and `cancel_provisioning` change that
state only after touch approval on the device.

The implemented runtime states are `unprovisioned` and `provisioning`.
`start_provisioning` is accepted only from `unprovisioned`, and
`cancel_provisioning` is accepted only from `provisioning`; other state
combinations return `invalid_state` without opening approval UI. `provisioned`
is not set because no root signing material exists. `locked` is not used
because no unlock model exists.

The setup-step v0 source path is `provisioning_setup_check`. It is accepted only
from `provisioning`, requires touch approval, returns
`provisioning_setup_check_result`, and leaves the provisioning state unchanged.
Firmware build passes for this path, and hardware smoke is still required. It is
not backup confirmation and does not generate, import, derive, store, or return
mnemonics, seeds, private keys, accounts, policies, or signing material.

Recovery phrase setup v0 source paths are `generate_recovery_phrase` and
`confirm_recovery_phrase_backup`. They are accepted only from `provisioning` and
require touch approval. `generate_recovery_phrase` uses an Agent-Q CSPRNG seeded
from early boot entropy before HAL initialization plus BIP-39 checksum logic to
create a 12-word DEV_PROFILE recovery phrase in RAM, then displays it on the
device only. The response contains only
`recovery_phrase_result`, status metadata, and `provisioning.state`. It never
contains the phrase, entropy, seed, private key, account data, or policy data.
The target tracks the volatile phrase with a RAM-only scratch substate:
`none`, `displayed`, or `backup_confirmation_pending`. This substate is
separate from persistent `provisioning.state`, pending approval, and the LVGL
panel pointer.

`confirm_recovery_phrase_backup` is accepted only after the scratch substate is
`displayed`. Accepting the request moves it to `backup_confirmation_pending`;
approval, rejection, or timeout wipes the volatile phrase and returns the
scratch substate to `none`. In this v0 slice it leaves the device in
`provisioning` rather than storing root material or moving to `provisioned`.
Firmware build passes for this path, and hardware smoke is still required.

The LVGL panel is not the source of truth for recovery phrase validity. If the
recovery phrase display panel is removed or replaced while the scratch substate
is `displayed`, the target treats that UI event as a transition to `none` and
wipes the volatile phrase. A later backup confirmation request must not succeed
for a phrase that is no longer visible. The active
`confirm_recovery_phrase_backup` approval prompt may replace the phrase display
only after validating that it was visible, and it must wipe the phrase on
approval, rejection, or timeout.

The phrase display has a finite lifetime. When it expires, the target clears the
setup panel, wipes the volatile phrase, and no later backup confirmation can use
that phrase.

`cancel_provisioning` wipes volatile setup scratch once its approval UI has
interrupted a recovery phrase display. If cancellation is rejected or times out,
the persistent state remains `provisioning`, but the displayed phrase is gone and
must be generated again. If scratch wipe succeeds but storing `unprovisioned`
fails after approval, the target reports `storage_error`, keeps the previous
persistent state, and does not restore the wiped phrase.

Mnemonic import, persistent signing material, account derivation, and signing
APIs are not implemented on this target.

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
The BIP-39 English wordlist is fetched from a pinned `bitcoin/bips` commit and
converted into generated firmware source during `prepare.sh`; the generated
wordlist source is not tracked.

## Verification

Current verification expectations for this target:

- run `tools/firmware/stackchan-cores3/test_bip39_vectors.sh` after ESP-IDF
  v5.5.4 is active to check known BIP-39 entropy-to-mnemonic vectors against
  the tracked encoder, ESP-IDF mbedTLS SHA-256, and generated wordlist source;
- build with `tools/firmware/stackchan-cores3/build.sh` after ESP-IDF v5.5.4 is
  active;
- flash to a StackChan CoreS3 device when hardware is available;
- smoke-test `get_status`;
- smoke-test `identify_device`;
- smoke-test `display_signal` approval, rejection, and timeout behavior;
- smoke-test `connect` approval, rejection, timeout, and `disconnect`;
- smoke-test `start_provisioning` approval, rejection, timeout, persistence
  across reboot, and `invalid_state` from the wrong state;
- smoke-test `cancel_provisioning` approval, rejection, timeout, persistence
  across reboot, and `invalid_state` from the wrong state;
- smoke-test `provisioning_setup_check` approval, rejection, timeout,
  `invalid_state` from `unprovisioned`, and unchanged `provisioning` state after
  approval;
- smoke-test `generate_recovery_phrase` approval, rejection, timeout,
  `invalid_state` from `unprovisioned`, no phrase in the host response, and
  device-only phrase display while state remains `provisioning`;
- smoke-test `get_status` reports `device.state = busy` while a recovery phrase
  is displayed;
- smoke-test recovery phrase display expiry clears the setup panel, wipes
  scratch, and makes backup confirmation return `invalid_setup_step`;
- smoke-test `confirm_recovery_phrase_backup` approval, rejection, timeout,
  `invalid_setup_step` before phrase display, unchanged `provisioning` state
  after approval, and scratch wipe;
- smoke-test `cancel_provisioning` wipes any displayed recovery phrase scratch;
- visually verify that Agent-Q temporary UI does not leave the avatar in an
  Agent-Q-specific mode after completion.
