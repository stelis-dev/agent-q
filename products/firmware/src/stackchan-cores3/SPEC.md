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

It is not the signing product yet. It does not persist chain private keys,
expose MCP directly, update policy, or sign user requests. It links a
restricted host-tested Sui transaction facts parser plus a common policy
evaluator, stores DEV_PROFILE root entropy and a DEV_PROFILE active
default-reject policy record plus a DEV_PROFILE local PIN verifier, and
consumes that policy decision only for Sui `sign_transaction`
policy-decision smoke.

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
| Provisioning status reporting | △ | Reports `unprovisioned`, material-backed `provisioned`, or `error` for persistent material inconsistency. Manual smoke observed `provisioned` after local setup and recovery setup on StackChan CoreS3; failure and consistency-error states still need targeted hardware checks. This is not signing readiness: read-only `get_accounts` and `get_policy` expose public/metadata state only, while signing remains unavailable. |
| Mnemonic UI flow v0 | △ | The local setup speech bubble opens a Generate/Recover choice. Generate creates DEV_PROFILE BIP-39 root entropy in RAM from an early-boot-seeded Agent-Q CSPRNG, displays only up-to-4-letter prefixes on device in a 3-column by 4-row grid, and advances to local 6-digit PIN entry after local backup confirmation. Recover accepts 12 BIP-39 words through a device-local 3-word-per-page prefix/candidate UI, verifies checksum, then enters the same PIN setup path. The target stores root entropy plus an active default-reject policy plus a salt/PIN verifier only after the repeated PIN matches. Three-letter BIP-39 words are displayed as the full word. The target keeps setup/recover volatile state and cleanup decisions in a provisioning-flow state module; USB/UI code routes events and renders the current state. Local controls own the setup transitions; there are no USB setup transition requests. Generate setup and PIN entry were manually smoke-tested after commit `2cb243b`; Recover was manually smoke-tested on StackChan CoreS3 during the recovery-entry slice. |
| `identify_device` | O | Shows a short code using temporary Agent-Q avatar UI. |
| `connect` | O | Source accepts connection only after material-backed `provisioned` state. Default connect approval requires local PIN entry on device; local settings can switch connect approval to physical Confirm after PIN verification. The session is RAM-only and does not authorize signing. Manual hardware smoke verified local PIN approval and fresh reconnect after USB detach/replug. Rerun hardware smoke after setup, session, or material-storage changes. |
| `disconnect` | O | Source clears only a matching RAM-only Firmware session and does not require persistent material readiness. It returns `busy` while local setup/PIN/reset or sensitive settings subflow state is active, including Change PIN, so external session teardown cannot interleave with device-local sensitive UI. Idle Settings menu does not block disconnect. Rerun hardware smoke after setup, session, or material-storage changes. |
| Local settings / material wipe | △ | Source implements device-local settings paths for `provisioned`: connect PIN toggle, Change PIN, and Reset. Change PIN verifies the current PIN, stores only a replacement salt/PIN verifier after repeated new PIN entry, and leaves root material/policy unchanged; storage failure either preserves the previous verifier or fails closed if the post-write verifier state cannot be proven. Reset wipes root material, active policy, PIN verifier, connect-approval setting, session, and returns to `unprovisioned`. Source also implements device-local destructive erase-only recovery from persistent-material consistency `error`, without PIN because the verifier may be unreadable, using the same reset-pending marker and wipe transaction. Host-triggered reset/debug/recovery/PIN-change protocol paths are intentionally not implemented. StackChan CoreS3 local reset was manually smoke-tested after commit `7c6e65c`; a manual session/settings smoke verified idle Settings read access, Change PIN session retention, and USB detach/replug session invalidation. Error-state erase recovery still needs hardware smoke. Rerun hardware smoke after settings or reset UI/state changes. |
| Agent-Q avatar UI | O | Uses an Agent-Q-owned top speech-bubble decorator and bottom decision strip. |
| Result feedback UI | O | Shows temporary result speech and returns to the default avatar. |
| Head movement feedback | O | Briefly raises the head for notification, approval, and success states. |
| Display power control | O | Turns the screen backlight off after three minutes of inactivity, skips the upstream screensaver, wakes for Agent-Q UI, toggles display power on side-button short press, and powers off on side-button long press. Before screen-off or power-off, the target moves to a rest posture; when the screen wakes, it returns to awake posture. |
| Boot/sleep posture | O | Centers yaw and raises pitch when the default avatar is attached at boot or the screen wakes. Moves to centered yaw and lowered pitch before screen-off or power-off. |
| Ed25519 signing self-test | △ | Runtime-generated test seed only; wiped after the self-test. Not a signing API. |
| `get_capabilities` | O | Source reports Sui Ed25519 account identity capability for account 0 over an approved session while material-backed `provisioned`; `methods` is empty until concrete signing methods are implemented. Rerun hardware smoke after setup, session, or material-storage changes. |
| `get_accounts` | O | Source derives the Sui Ed25519 account (index 0, `m/44'/784'/0'/0'/0'`) from the stored DEV_PROFILE root entropy and returns address + public key over an approved session while `provisioned`. Read-only; private material never leaves Firmware. Derivation is verified against Sui SDK address vectors on host; manual hardware smoke verified this path while idle Settings is open, after Change PIN on the same session, and after reconnect. Rerun hardware smoke after setup, session, or material-storage changes. |
| `get_policy` | △ | Source implements a session-scoped read-only summary of the active DEV_PROFILE default-reject policy (`agentq.policy.v0`, hash id, `reject`, zero rules). Corrupt/unreadable policy fails closed; missing policy is migrated only for legacy root-only DEV_PROFILE devices. Gateway/MCP parser tests, target policy-store host tests, and manual hardware smoke for idle-Settings read access cover this path. |
| `call_method` | △ | Runtime skeleton exists. It requires material-backed `provisioned` plus a matching active session, keeps unknown methods rejected with `unsupported_method`, and recognizes Sui `sign_transaction` only for restricted-transfer policy-decision smoke. It consumes the stored active default-reject policy; corrupt/unreadable policy is a material-consistency error rather than a normal `provisioned` state, while missing policy is migrated only for legacy root-only DEV_PROFILE devices. Host tests cover the request field/type validation helper and policy store provider. Hardware smoke remains required for the stored-policy path. No approval UI, capability advertisement, or signing is connected. |
| Persistent signing material | △ | DEV_PROFILE root entropy NVS blob exists after backup confirmation plus matching PIN repeat. Public account derivation is implemented (`get_accounts`, Sui Ed25519 account 0). Signing use, USER_PROFILE secure storage, and import are not implemented. |
| Mnemonic generation/import | △ | DEV_PROFILE recovery phrase generation/display, device-local mnemonic recovery entry, local 6-digit PIN setup, and backup-confirmed/checksum-verified root entropy storage source exists. USB/Gateway/MCP mnemonic import and USER_PROFILE secure provisioning are not implemented. |
| Provisioning flow | △ | DEV_PROFILE mnemonic UI and material-backed `provisioned` state source exists. Backup confirmation plus matching PIN repeat stores root entropy, initializes the active default-reject policy, and stores the local PIN verifier. Public account derivation is implemented via `get_accounts`; signing and USER_PROFILE secure provisioning are not implemented. |
| Policy evaluator foundation | △ | Links the common host-tested policy evaluator, stored-policy provider boundary, and Sui restricted-transfer facts adapter. Sui `sign_transaction` consumes the stored active default-reject decision only as a rejected policy-decision smoke result; it does not sign. |
| Policy storage/read | △ | Stores only the DEV_PROFILE active default-reject policy record in NVS, exposes a read-only `get_policy` summary, migrates legacy root-only missing policy to the default-reject record, and treats corrupt/unreadable records as a material-consistency error. Policy update authorization and custom policy content are not implemented. |
| Policy update | X | Not implemented. |
| Secure user profile | X | Not implemented. |

## Chain And Method Support

This target currently has no user-facing chain signing API. Chain code is
limited to a Sui Ed25519 boot-time self-test, read-only public account identity
capability/account reporting, and the common restricted Sui transaction facts
parser; none of these are signing APIs.

| Chain / method | Status | Notes |
|---|---:|---|
| Sui Ed25519 self-test | △ | Diagnostic only. It proves the signing dependency links and works on-device. |
| Sui `sign_personal_message` | X | Not implemented. |
| Sui `sign_transaction` | △ | This method is recognized inside `call_method` only for policy-decision smoke. It validates `network` and base64 `txBytes`, decodes the restricted SUI transfer shape, consumes the stored active default-reject policy runtime decision, and returns a rejected `method_result`; corrupt/unreadable policy fails closed as material inconsistency before normal session-scoped methods are available, and missing policy is migrated only for legacy root-only DEV_PROFILE devices. It is not advertised in `get_capabilities`, does not sign, and does not trigger approval UI. Hardware smoke remains required for the stored-policy path. |
| Sui txBytes decoding | △ | The StackChan build links the common restricted SUI transfer facts parser. Host fixtures cover valid SUI transfer facts and malformed/unsupported rejects. The runtime connects it only to Sui `sign_transaction` policy-decision smoke, not capability advertisement or signing. |
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
- bottom decision strip for Cancel/Confirm;
- temporary emotion override;
- temporary head movement feedback.

Agent-Q must remove only its own temporary UI. It must not force a dedicated
Agent-Q app mode for normal requests.

Current UI behavior:

| Request or state | UI behavior | Firmware state |
|---|---|---|
| `unprovisioned` idle | Touchable setup speech bubble | `idle` |
| `get_status` | No UI | `idle` unless approval UI, setup material, sensitive local subflow, or material/state error is active |
| `identify_device` | Temporary speech bubble with short code | `idle` |
| Local setup choice | Temporary Generate/Recover setup panel | `busy` |
| Recovery phrase displayed | Temporary setup panel with 12 numbered up-to-4-letter prefixes in 3 columns by 4 rows and bottom Cancel/Confirm buttons | `busy` |
| Mnemonic recovery entry | Temporary setup panel with three numbered word cells, A-Z prefix buttons, scrollable BIP-39 candidate bubbles, and local Cancel/Clear/Previous/Next controls | `busy` |
| Local recovery phrase Confirm | Uses the recovery phrase panel's bottom Confirm button and advances to local PIN entry | `busy` |
| Local PIN setup | Temporary setup panel with numeric keypad, masked 6-digit entry, Clear, backspace icon, Cancel, and Confirm | `busy` |
| Local settings menu | Temporary settings menu with fixed label/control rows. Current implemented actions are connect PIN toggle, Change PIN, and Reset. Each sensitive action opens local PIN verification directly. | `idle` while the menu is idle; `busy` after entering a sensitive subflow |
| Local recovery phrase Cancel | Uses the recovery phrase panel's bottom Cancel button | `idle` after scratch wipe |
| Approved result | Temporary success speech and emotion | `idle` |
| Rejected result | Temporary rejected speech and emotion | `idle` |
| Timeout result | Temporary timeout speech and emotion | `idle` |

`idle` means no physical approval prompt, device-only setup material, or
sensitive local subflow is active. An idle Settings menu is local UI, but it does
not block existing session-scoped read or cleanup requests, so status remains
`idle`. Recovery phrase display and PIN setup report `busy` so Gateway status
does not imply that UI-replacing setup requests are available.

The StackChan default avatar face remains visible. Agent-Q does not use the
upstream default speech bubble at runtime; it uses the Agent-Q-owned speech
bubble decorator so request UI ownership is explicit.

## Display Power And Posture

Display power and head posture are target-local runtime state. They must not
gate protocol APIs, provisioning, sessions, accounts, policy, or signing.

The Agent-Q StackChan CoreS3 build replaces the upstream screensaver with
display-power control:

- three minutes of LVGL inactivity turns the screen backlight off;
- Agent-Q request UI wakes the screen before showing setup material,
  notifications, or physical approval prompts;
- side-button short press toggles display power;
- side-button long press powers the device off.

The display-power state is owned by `agent_q_display_power`. StackChan-specific
motor posture and transient head-motion feedback are owned by
`agent_q_motion_state`. The board layer only translates AXP2101 power-key IRQs
into display-power events, target-local motion posture for power-off, or
hardware power-off; it does not change Agent-Q product state.

Boot posture is StackChan-specific motion feedback. After the default avatar is
attached, the Agent-Q build centers yaw and raises pitch (`yaw=0`, `pitch=540`).
Temporary Agent-Q head movement feedback may run during local notifications and
approvals, then returns control to StackChan motion.

Sleep and wake posture are also StackChan-specific motion feedback. Before
automatic screen-off, manual screen-off, or side-button power-off, the target
moves to centered yaw and lowered pitch (`yaw=0`, `pitch=0`). When the screen
wakes by touch, side-button toggle, or Agent-Q request UI, the target returns to
centered yaw and raised pitch (`yaw=0`, `pitch=540`). These posture changes are
not product state and must not clear sessions, provisioning scratch, accounts,
or pending approvals.

## Session Model

`connect` is defined by the shared protocol and is accepted only after the
target is material-backed `provisioned`. The session id is generated by
Firmware and held in RAM. A new approved `connect` replaces the previous
Firmware session. Gateway sends a Firmware `connect` request each time it asks
to connect; Gateway-local session reuse is not used for `connect_device`.

By default this target requires a device-local 6-digit PIN for `connect`.
Successful PIN entry is the connect approval; there is no additional Confirm
step after PIN success. A device-local settings toggle can switch connect
approval to the physical Confirm path, but changing that toggle also requires
stored PIN verification. The toggle is stored as `requirePinOnConnect`: a
missing key means the secure default, ON; an invalid value fails closed to ON
and is logged. When the target cannot read the setting, the settings menu shows
the fail-closed value but disables the toggle instead of allowing a write from
an uncertain source state. PIN entry is never submitted over USB.

USB link loss clears the Firmware RAM session by policy. For this target,
USB connected means USB host SOF is observed through
`usb_serial_jtag_is_connected()`. It does not prove Gateway is running or that
the serial port is open, so cable removal, host sleep/suspend, or SOF loss may
end the session before `sessionTtlMs`.

`disconnect` clears the session only when the supplied session id matches the
active Firmware session. It is a session-lifecycle operation, so material
readiness is not required; if a consistency error has already cleared the
session, `disconnect` returns `invalid_session`.

Sessions do not authorize signing. They only establish a communication session
for future session-scoped protocol requests.

## Persistent Storage

This target persists the protocol `deviceId`, the provisioning state flag, a
DEV_PROFILE binary root entropy blob, the DEV_PROFILE active default-reject
policy record, and a DEV_PROFILE local PIN verifier in ordinary NVS after
physical backup confirmation plus matching PIN repeat. The provisioning state
flag is not signing material by itself and does not make the device ready to
sign. The target reports `provisioned` only when the persisted state, valid root
entropy blob, valid active policy record, and valid local PIN verifier all
exist. If those records disagree after boot or during runtime checks, the target
reports `provisioning.state = error` and fails closed. It does not store the
mnemonic display string, prefixes, seed, or account data to NVS. The local PIN
verifier is a UX gate for local reset and future sensitive writes; it is not
root-material encryption.
For DEV_PROFILE upgrade compatibility, if the target boots with the previous
development shape (`prov_state = provisioned` and valid root entropy, but no
policy record), it initializes the default-reject active policy before reporting
`provisioned`; failure to initialize that policy enters material/state
consistency error. Existing DEV_PROFILE devices without the local PIN verifier
are not migrated and fail closed until reprovisioned.

| Namespace | Key | Purpose |
|---|---|---|
| `agent_q` | `device_id` | Gateway reconnect and device-selection identity |
| `agent_q` | `prov_state` | Provisioning state flag; `provisioned` is valid only with root entropy, active policy, and local PIN verifier present |
| `agent_q` | `root_entropy` | DEV_PROFILE BIP-39 root entropy blob; not exported over USB |
| `agent_q` | `policy_v0` | DEV_PROFILE active default-reject policy record |
| `agent_q` | `pin_auth` | DEV_PROFILE salt + PBKDF2-HMAC-SHA512 local PIN verifier; not root encryption |
| `agent_q` | `pin_on_connect` | Optional local connect approval setting; missing means require PIN on connect; local reset erases it back to the missing-key default |
| `agent_q` | `reset_pending` | Internal Firmware-owned marker used to resume an interrupted local reset wipe at boot; not a protocol state or host API |

Agent-Q-owned modules are sources under `agent_q/` in this target tree. These
modules may share the `agent_q` namespace. New keys should be named by feature,
such as `<feature>_<name>`, to avoid collisions. ESP-IDF NVS key names are
limited to 15 characters, so this target uses `prov_state` rather than the
longer protocol field name `provisioning.state`.

## Provisioning Capability

Provisioning status reporting, the mnemonic UI flow, and DEV_PROFILE root
entropy persistence are implemented in the target firmware source. Hardware
smoke is still required. `get_status` returns `provisioning.state`.

Setup transition paths are local device UX only. The target does not implement
USB requests for setup start, setup cancel, recovery phrase backup
confirmation, mnemonic import/recovery, factory reset, or diagnostic display
signaling. `provisioned` is set only after local backup confirmation or
checksum-verified local recovery, matching local PIN repeat, and successful
root entropy, active policy, local PIN verifier, and provisioning-state
persistence. `locked` is not used because no unlock model exists.

Recovery phrase setup v0 starts from the local setup speech bubble shown while
the device is `unprovisioned`, then shows local Generate and Recover choices.
Generate uses an Agent-Q CSPRNG seeded from early boot entropy before HAL
initialization plus BIP-39 checksum logic to create a 12-word DEV_PROFILE
recovery phrase in RAM, then displays only the up-to-4-letter word prefixes on
the device in a 3-column by 4-row grid. Three-letter BIP-39 words are displayed
as the full word. Recover uses a device-local word-entry panel with three
numbered word cells per page for four pages. The user taps a cell, enters a
BIP-39 prefix through local A-Z buttons, and selects a matching word from
scrollable on-device candidate bubbles. BIP-39 English prefixes and recovered
words are secret material. No protocol response contains the phrase, prefixes,
recovered words, entropy, seed, private key, account data, or policy data.
The target tracks volatile setup with RAM-only scratch substates: `none`,
`setup_choice`, `recovery_phrase_displayed`, `recover_word_entry`,
`pin_first_entry`, `pin_repeat_entry`, and `pin_committing`. This substate is
separate from persistent
`provisioning.state`, session state, display power state, and the LVGL panel
pointer.

Recover `Next` is enabled only when all three words on the current page are
selected. After 12 words are selected, Firmware reconstructs 128-bit BIP-39
entropy and verifies the checksum before entering PIN setup. Checksum failure
stores nothing and keeps recovery entry active. Cancel, timeout, panel
deletion, or display allocation failure wipes recovery scratch and leaves the
target `unprovisioned`.

Backup confirmation is accepted only from the recovery phrase panel's local
Confirm button after the scratch substate is `recovery_phrase_displayed`. The
device-local Confirm button advances to local PIN entry; it does not store
persistent material by itself. The recovery path reaches the same PIN entry only
after 12 selected BIP-39 words pass checksum validation. The PIN entry screen
accepts exactly six digits, asks for a repeat, wipes typed PIN scratch on
mismatch, and returns to first PIN entry while retaining root entropy scratch.
Matching PIN repeat enters
`pin_committing`, keeps the PIN panel active with a non-interactive processing
overlay, stores the DEV_PROFILE root entropy blob, stores the active
default-reject policy, stores a salt + PIN verifier, persists `provisioned`, and
then wipes volatile scratch. Storage failure rolls back persistent setup
material where possible, wipes scratch, and must not report `provisioned`.
StackChan CoreS3 Generate setup and PIN entry were manually smoke-tested after
commit `2cb243b`; Recover entry was manually smoke-tested on StackChan CoreS3
during the recovery-entry slice. Rerun hardware smoke after setup UI or state
changes.

The LVGL panel is not the source of truth for setup scratch validity. If the
recovery phrase display or PIN panel is removed or replaced while the matching
scratch substate is active, the target treats that UI event as a transition to
`none` and wipes the volatile setup scratch. A later backup confirmation or PIN
submit event must not succeed for setup material whose panel is gone. Display
power state is not part of this security state: screen/backlight sleep alone
does not invalidate scratch, and Agent-Q UI wakes the display before showing
setup material.

The phrase display and PIN setup panel have finite lifetimes. When either
expires, the target clears the setup panel, wipes volatile setup scratch, and no
later backup confirmation or PIN submit can use that scratch.

The device-local Cancel button wipes volatile setup scratch and leaves
persistent state `unprovisioned`. Cancellation does not erase already-confirmed
root material, active policy, or PIN verifier.

Local settings actions are separate device-local flows under `provisioned`.
The target enters local settings only when no setup, approval, identification,
or Agent-Q temporary UI is active. The settings screen presents fixed
label/control rows and Close as the only bottom action. Current implemented
settings actions are the connect PIN toggle, Change PIN, and Reset. Selecting a
sensitive action opens stored 6-digit PIN verification directly. Change PIN then
accepts and repeats a new 6-digit PIN, stores only the replacement salt/verifier,
and returns to Settings without ending the active RAM session; storage failure
either leaves the old verifier in place or fails closed if the post-write
verifier state cannot be proven.
Opening or closing the Settings menu alone does not end the active RAM session.
While the Settings menu is idle, existing session-scoped requests remain
available; PIN verification, PIN change, and Reset subflows return `busy` until
the local flow completes or is canceled.
Canceling connect-toggle, Change PIN, or Reset PIN verification, and
successfully changing the connect-toggle setting or PIN verifier, return to the
settings menu instead of closing local settings. Successfully changing the
connect-approval setting affects the next `connect`; it does not end the current
active RAM session.
Wrong PIN, timeout, or cancel leaves root material, active policy, PIN verifier,
the local connect setting, and `provisioned` state intact.
After Reset PIN confirm, the target keeps the reset PIN panel active and adds a
non-interactive processing overlay before PIN verification. Correct PIN
verification advances to destructive wipe while keeping the processing overlay
active, then wipes root material, active policy, PIN verifier, the local
connect setting, runtime session, and provisioning state before reporting
`unprovisioned`. Before destructive wipe starts, Firmware writes an internal
reset-pending marker; if power is lost
mid-reset, boot resumes the material wipe before loading normal state. If the
marker cannot be written, reset aborts before material is wiped. After the
marker is written, partial wipe, marker-clear, or state persistence failure
enters material/state consistency error. This reset flow is not exposed over USB.
When the target detects a material/state consistency error, it clears any active
RAM session immediately and fails closed for session-scoped requests. The error
panel offers only a device-local destructive erase recovery: it cannot read,
repair, unlock, or export stored material, it does not require PIN because the
PIN verifier may be unreadable, and it uses the same reset-pending marker plus
material wipe transaction before returning to `unprovisioned`. Connect,
settings, Change PIN, and reset PIN verification share one RAM-only
5-failure, 30-second stored-PIN attempt budget. Closing one local PIN flow and
opening another does not clear that budget. Power cycling clears the local
lockout.

Read-only public account derivation (`get_accounts`) is implemented. Mnemonic
import, runtime policy APIs, signing APIs, and USER_PROFILE secure
root-material handling are not implemented on this target.

StackChan CoreS3 has a display and touch input, so it is a candidate for a
future local provisioning flow:

- generate a new mnemonic on the device;
- show the mnemonic on the device once for backup;
- require local confirmation before storing it;
- require local 6-digit PIN entry/repeat before storing it;
- accept imported mnemonic input only through an explicitly weaker setup path;
- expose only public keys and addresses after provisioning.

Until signing and signing policy exist, this target must not be described as
signing-ready.

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
- run `tools/firmware/stackchan-cores3/test_local_auth.sh` to check local
  6-digit PIN verifier storage, verification, fresh salt, wipe, and fail-closed
  behavior against host NVS/RNG stubs and pinned Monocypher;
- run `tools/firmware/stackchan-cores3/test_local_pin_auth.sh` to check local
  PIN authorization state transitions, including lockout release and retry
  deadline refresh;
- run `tools/firmware/stackchan-cores3/test_local_reset.sh` to check local reset
  and error-state erase recovery state transitions, reset-pending marker
  behavior, destructive wipe orchestration, and failure cleanup against host
  NVS/material stubs;
- run `tools/firmware/stackchan-cores3/test_provisioning_flow.sh` to check
  Generate/Recover/setup-PIN volatile state transitions, scratch lifetime,
  panel-loss cleanup, and commit readiness against host stubs;
- run `tools/firmware/stackchan-cores3/test_connect_settings.sh` to check the
  connect-approval setting's missing-key secure default, stored OFF override,
  invalid value fail-closed behavior, and reset wipe back to the missing-key
  default;
- build with `tools/firmware/stackchan-cores3/build.sh` after ESP-IDF v5.5.4 is
  active;
- flash to a StackChan CoreS3 device when hardware is available;
- smoke-test `get_status`;
- smoke-test `identify_device`;
- smoke-test `connect` returns `invalid_state` before `provisioned`;
- manually enter setup from the local unprovisioned setup speech bubble;
- visually verify the recovery phrase panel displays 12 numbered
  up-to-4-letter prefixes in a 3-column by 4-row grid and that three-letter
  BIP-39 words are displayed as the full word;
- smoke-test local Cancel wipes scratch and leaves `provisioning.state =
  unprovisioned`;
- smoke-test local Confirm advances to local PIN setup without storing material;
- smoke-test matching local PIN repeat stores root material plus active
  default-reject policy plus local PIN verifier, wipes scratch, and reports
  `provisioning.state = provisioned`;
- smoke-test PIN mismatch wipes typed PIN scratch only and retries first PIN
  entry;
- smoke-test PIN cancel/timeout wipes PIN plus root scratch and remains
  `unprovisioned`;
- smoke-test reboot persistence after matching PIN repeat;
- smoke-test `connect` after backup-confirmed root material, active policy, and
  local PIN verifier storage requires local PIN by default and returns a
  RAM-only session id;
- smoke-test local settings connect PIN toggle requires current PIN, changes
  only that local setting, and leaves it unchanged after wrong PIN, cancel, or
  timeout;
- smoke-test local settings Change PIN requires the current PIN, stores the new
  PIN only after repeated new PIN entry, leaves the old PIN valid on mismatch,
  cancel, timeout, or storage failure, and never changes root material or policy;
- smoke-test USB host SOF loss clears the Firmware RAM session;
- smoke-test `disconnect` clears a matching active session and rejects an
  unknown or expired session id;
- smoke-test local settings reset from `provisioned`: wrong PIN leaves
  `provisioned` material intact, cancel/timeout leaves material intact, correct
  PIN wipes root material, active policy, PIN verifier, connect-approval
  setting, and session, then `get_status` reports `unprovisioned`;
- smoke-test three minutes of inactivity turns the screen backlight off, Agent-Q
  request UI wakes it, side-button short press toggles display power, and
  side-button long press powers off;
- visually verify boot posture centers yaw and raises pitch after the default
  avatar attaches;
- visually verify automatic screen-off, manual screen-off, and side-button
  power-off move the target to centered yaw and lowered pitch first;
- visually verify touch, side-button wake, and Agent-Q request UI wake return
  the target to centered yaw and raised pitch;
- smoke-test `get_status` reports `device.state = busy` while a recovery phrase
  is displayed;
- smoke-test recovery phrase display expiry clears the setup panel, wipes
  scratch, and prevents later local confirmation;
- visually verify that Agent-Q temporary UI does not leave the avatar in an
  Agent-Q-specific mode after completion.
