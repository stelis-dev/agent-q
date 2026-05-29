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
| Provisioning status reporting | △ | Reports `unprovisioned` or material-backed `provisioned`; hardware smoke is still required. This is not signing readiness because accounts, policy, and signing are unavailable. |
| Mnemonic UI flow v0 | △ | Approved `start_provisioning` or the local setup speech bubble generates DEV_PROFILE BIP-39 root entropy into RAM from an early-boot-seeded Agent-Q CSPRNG, displays only up-to-4-letter prefixes on device in a 3-column by 4-row grid, and stores the root entropy only after physical backup confirmation. Three-letter BIP-39 words are displayed as the full word. `confirm_recovery_phrase_backup` and `cancel_provisioning` wipe scratch. Hardware smoke is still required. |
| `identify_device` | O | Shows a short code using temporary Agent-Q avatar UI. |
| `display_signal` diagnostic | O | Shows a decision UI and returns after touch approval, rejection, or timeout. |
| `connect` | △ | Accepted only after material-backed `provisioned` state and physical approval. The session is RAM-only and does not authorize signing. Hardware smoke is still required. |
| `disconnect` | △ | Clears a matching RAM-only Firmware session after material-backed `provisioned` state. Hardware smoke is still required. |
| `factory_reset` | △ | Requires physical approval, erases DEV_PROFILE root entropy, clears RAM session/setup scratch, persists `unprovisioned`, and recovers from material/state consistency errors. Hardware smoke is still required. |
| Agent-Q avatar UI | O | Uses an Agent-Q-owned speech-bubble decorator and top decision strip. |
| Result feedback UI | O | Shows temporary result speech and returns to the default avatar. |
| Head movement feedback | O | Briefly raises the head for notification, approval, and success states. |
| Display power control | O | Turns the screen backlight off after one minute of inactivity, skips the upstream screensaver, wakes for Agent-Q UI, toggles display power on side-button short press, and powers off on side-button long press. |
| Boot posture | O | Centers yaw and raises pitch when the default avatar is attached at boot. |
| Ed25519 signing self-test | △ | Runtime-generated test seed only; wiped after the self-test. Not a signing API. |
| `get_capabilities` | X | Not implemented. |
| `get_accounts` | X | Not implemented. |
| `call_method` | X | Not implemented. |
| Persistent signing material | △ | DEV_PROFILE root entropy NVS blob exists after backup confirmation. Account derivation, signing use, USER_PROFILE secure storage, and import are not implemented. |
| Mnemonic generation/import | △ | DEV_PROFILE recovery phrase generation/display and backup-confirmed root entropy storage source exists. Mnemonic import and USER_PROFILE secure provisioning are not implemented. |
| Provisioning flow | △ | DEV_PROFILE mnemonic UI and material-backed `provisioned` state source exists. Account derivation, policy, signing, and USER_PROFILE secure provisioning are not implemented. |
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
| `unprovisioned` idle | Touchable setup speech bubble | `idle` |
| `get_status` | No UI | `idle` unless approval UI is active |
| `identify_device` | Temporary speech bubble with short code | `idle` |
| `display_signal` pending | Speech bubble plus top Cancel/Confirm strip | `awaiting_approval` |
| `start_provisioning` pending | Speech bubble plus top Cancel/Confirm strip | `awaiting_approval` |
| `cancel_provisioning` pending | Speech bubble plus top Cancel/Confirm strip | `awaiting_approval` |
| Recovery phrase displayed | Temporary setup panel with 12 numbered up-to-4-letter prefixes in 3 columns by 4 rows | `busy` |
| `confirm_recovery_phrase_backup` pending | Speech bubble plus top Cancel/Confirm strip | `awaiting_approval` |
| `factory_reset` pending | Speech bubble plus top Cancel/Confirm strip | `awaiting_approval` |
| Approved result | Temporary success speech and emotion | `idle` |
| Rejected result | Temporary rejected speech and emotion | `idle` |
| Timeout result | Temporary timeout speech and emotion | `idle` |

`idle` means no physical approval prompt or device-only setup material is
active. Recovery phrase display reports `busy` so Gateway status does not imply
that UI-replacing setup requests are available.

The StackChan default avatar face remains visible. Agent-Q does not use the
upstream default speech bubble at runtime; it uses the Agent-Q-owned speech
bubble decorator so request UI ownership is explicit.

## Display Power And Posture

Display power and head posture are target-local runtime state. They must not
gate protocol APIs, provisioning, sessions, accounts, policy, or signing.

The Agent-Q StackChan CoreS3 build replaces the upstream screensaver with
display-power control:

- one minute of LVGL inactivity turns the screen backlight off;
- Agent-Q request UI wakes the screen before showing setup material,
  notifications, or physical approval prompts;
- side-button short press toggles display power;
- side-button long press powers the device off.

The display-power state is owned by `agent_q_display_power`. The board layer
only translates AXP2101 power-key IRQs into display-power events or hardware
power-off; it does not change Agent-Q product state.

Boot posture is StackChan-specific motion feedback. After the default avatar is
attached, the Agent-Q build centers yaw and raises pitch (`yaw=0`, `pitch=540`).
Temporary Agent-Q head movement feedback may run during local notifications and
approvals, then returns control to StackChan motion.

## Session Model

`connect` is defined by the shared protocol and is accepted only after the
target is material-backed `provisioned`. The session id is generated by
Firmware and held in RAM. A new approved `connect` replaces the previous
Firmware session.

`disconnect` clears the session only when the supplied session id matches the
active Firmware session.

Sessions do not authorize signing. They only establish a communication session
for future session-scoped protocol requests.

## Persistent Storage

This target persists the protocol `deviceId`, the provisioning state flag, and
a DEV_PROFILE binary root entropy blob in ordinary NVS after physical backup
confirmation. The provisioning state flag is not signing material by itself and
does not make the device ready to sign. The target reports `provisioned` only
when the persisted state and valid root entropy blob both exist. It does not
store the mnemonic display string, prefixes, seed, account, or policy data to
NVS.

| Namespace | Key | Purpose |
|---|---|---|
| `agent_q` | `device_id` | Gateway reconnect and device-selection identity |
| `agent_q` | `prov_state` | Provisioning state flag; `provisioned` is valid only with root entropy present |
| `agent_q` | `root_entropy` | DEV_PROFILE BIP-39 root entropy blob; not exported over USB |

Agent-Q-owned modules are sources under `agent_q/` in this target tree. These
modules may share the `agent_q` namespace. New keys should be named by feature,
such as `<feature>_<name>`, to avoid collisions. ESP-IDF NVS key names are
limited to 15 characters, so this target uses `prov_state` rather than the
longer protocol field name `provisioning.state`.

## Provisioning Capability

Provisioning status reporting, the mnemonic UI flow, and DEV_PROFILE root
entropy persistence are implemented in the target firmware source. Hardware
smoke is still required. `get_status` returns `provisioning.state`.

`start_provisioning` is accepted only while persistent state is
`unprovisioned` and no mnemonic setup scratch is active. `cancel_provisioning`
is accepted only while mnemonic setup scratch or its confirmation prompt is
active; other state combinations return `invalid_state` without opening
approval UI. `provisioned` is set only after physical backup confirmation and
successful root entropy plus provisioning-state persistence. `locked` is not
used because no unlock model exists.

Recovery phrase setup v0 source paths are approved `start_provisioning`,
`confirm_recovery_phrase_backup`, and `cancel_provisioning`. `start_provisioning`
uses an Agent-Q CSPRNG seeded from early boot entropy before HAL initialization
plus BIP-39 checksum logic to create a 12-word DEV_PROFILE recovery phrase in
RAM, then displays only the up-to-4-letter word prefixes on the device in a
3-column by 4-row grid. Three-letter BIP-39 words are displayed as the full
word. BIP-39 English prefixes identify the words and are secret material. The
response contains only `recovery_phrase_result`, status
metadata, and `provisioning.state`. The display response reports
`unprovisioned`; the confirmed response reports `provisioned` only after root
entropy storage succeeds. It never contains the
phrase, prefixes, entropy, seed, private key, account data, or policy data.
The target tracks the volatile phrase with a RAM-only scratch substate:
`none`, `displayed`, or `backup_confirmation_pending`. This substate is
separate from persistent `provisioning.state`, pending approval, and the LVGL
panel pointer.

`confirm_recovery_phrase_backup` is accepted only after the scratch substate is
`displayed`. Accepting the request moves it to `backup_confirmation_pending`;
approval, rejection, or timeout wipes the volatile phrase and returns the
scratch substate to `none`. Approval stores the DEV_PROFILE root entropy blob,
persists `provisioned`, and then wipes volatile scratch. Storage failure wipes
scratch, returns `storage_error`, and must not report `provisioned`. Hardware
smoke is still required.

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
the displayed phrase is gone and must be generated again. Cancellation does not
erase already-confirmed root material; `factory_reset` owns that operation.

`factory_reset` is accepted with physical approval from normal states and from
the internal material/state consistency-error condition. Approval clears any
RAM session, wipes volatile setup scratch, erases the DEV_PROFILE root entropy
blob, persists `unprovisioned`, and clears the consistency error only after
storage cleanup succeeds. Rejection and timeout leave stored material and state
unchanged.

Mnemonic import, account derivation, policy, signing APIs, and USER_PROFILE
secure root-material handling are not implemented on this target.

StackChan CoreS3 has a display and touch input, so it is a candidate for a
future local provisioning flow:

- generate a new mnemonic on the device;
- show the mnemonic on the device once for backup;
- require local confirmation before storing it;
- accept imported mnemonic input only through an explicitly weaker setup path;
- expose only public keys and addresses after provisioning.

Until account derivation and signing policy exist, this target must not be
described as signing-ready.

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
- smoke-test `connect` returns `invalid_state` before `provisioned`;
- smoke-test `connect` after backup-confirmed root material storage requires
  physical approval and returns a RAM-only session id;
- smoke-test `disconnect` clears a matching active session and rejects an
  unknown or expired session id;
- smoke-test `factory_reset` requires physical approval, clears a matching
  active session, returns `unprovisioned`, and allows `start_provisioning`
  again;
- smoke-test `factory_reset` recovers a material/state consistency-error device
  when such a condition can be safely induced in a development build;
- smoke-test one minute of inactivity turns the screen backlight off, Agent-Q
  request UI wakes it, side-button short press toggles display power, and
  side-button long press powers off;
- visually verify boot posture centers yaw and raises pitch after the default
  avatar attaches;
- smoke-test `start_provisioning` approval, rejection, timeout, displayed
  3-column by 4-row prefix UI, unchanged `unprovisioned` state, and `busy`
  while setup scratch is active;
- smoke-test `cancel_provisioning` approval, rejection, timeout,
  `invalid_state` when no setup flow is active, unchanged `unprovisioned`
  state, and scratch wipe;
- smoke-test `get_status` reports `device.state = busy` while a recovery phrase
  is displayed;
- smoke-test recovery phrase display expiry clears the setup panel, wipes
  scratch, and makes backup confirmation return `invalid_setup_step`;
- smoke-test `confirm_recovery_phrase_backup` approval, rejection, timeout,
  `invalid_setup_step` before phrase display, `provisioned` state after
  approved storage, unchanged `unprovisioned` state after rejection or timeout,
  and scratch wipe;
- smoke-test `cancel_provisioning` wipes any displayed recovery phrase scratch;
- visually verify that Agent-Q temporary UI does not leave the avatar in an
  Agent-Q-specific mode after completion.
