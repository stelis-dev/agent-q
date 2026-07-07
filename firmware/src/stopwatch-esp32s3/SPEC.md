# StopWatch ESP32-S3 Firmware Specification

This document describes the current StopWatch ESP32-S3 Firmware target.

The shared host process/Firmware protocol is defined in `specs/PROTOCOL.md`.
This target must fit that protocol and must not define StopWatch-specific
product APIs.

## Target Role

StopWatch ESP32-S3 is a target-local validation target for multi-hardware
Firmware structure.

Its current role is:

- boot a target-local app on the StopWatch display;
- expose a USB Serial/JTAG newline-delimited JSON transport for the implemented
  local-authentication, Sui zkLogin proof-bootstrap, and user-confirmed Sui
  signing slices;
- report shared status projection through `get_status`;
- create a Firmware session after device-local `connect` approval;
- install a Sui zkLogin proof through the shared credential methods and
  payload-transfer transport after device-local proof review;
- project the active Sui zkLogin account through the shared account schema;
- provide shared failure responses for methods that are unavailable in this
  target state or slice;
- sign Sui personal messages for the active Sui zkLogin account after
  device-local user confirmation;
- sign Sui transactions for the active Sui zkLogin account after either
  device-local user confirmation or policy authorization, according to the
  stored signing authorization mode;
- store the current policy document, expose `policy_get`, review and apply
  `policy_propose` through device-local confirmation, and record approval
  history for policy updates and signing decisions;
- provide local display, touch, physical button, and vibration feedback for this
  slice;
- provide target-local power-button behavior.

It does not expose MCP directly, does not provide chain-specific signing APIs,
and does not provide host-triggered signing-mode selection.

## Target Status

Legend:

- `O`: implemented for this target.
- `X`: not implemented for this target.
- `N/A`: not applicable to this target.

| Capability | Status | Notes |
|---|---:|---|
| USB JSONL transport | O | Uses ESP32-S3 USB Serial/JTAG. |
| `get_status` | O | Reports shared status projection for first-run setup, local-authentication lock, neutral idle, active zkLogin proof, and error states. |
| Local authentication setup | O | User creates a 1-to-4 digit rotary telephone-style passcode on the round display and repeats it before storage. |
| Local authentication verification | O | Stores a salted verifier, failed-attempt count, lock tier, and lock duration. Raw passcode input is not stored. |
| Device reset | O | Device-local destructive reset. From idle, KEYB opens reset review and local-authentication confirmation performs Device reset. If the local-authentication record is invalid or unreadable, KEYB on the error screen performs the same Device reset because local authentication cannot be verified. Device reset clears local authentication, the active zkLogin credential, mutable settings, session state, pending state, retained responses, and signing scratch, then returns to first-run local-authentication setup. |
| `identify_device` | O | Shows a short temporary identification code on the display and returns the shared identify result. |
| `connect` | O | Requires local authentication and device-local approval when no session is active. A live same-link session returns the existing session without a second approval. Locked local authentication fails with `auth_unavailable`. |
| Firmware sessions | O | Sessions are volatile and USB-link-bound. The advertised `sessionTtlMs` is `4294967295`. Sessions clear on `disconnect`, reset/reboot, Device reset, credential consistency error, or USB removal after the grace window expires. |
| `disconnect` session cleanup | O | Clears session-scoped credential preparation, payload transfer, pending proof review, and pending request state. |
| `get_capabilities` | O | With a valid session, reports Sui zkLogin credential operations while no proof is active. With an active proof, reports the active Sui account and user-confirmed Sui signing methods. |
| `get_accounts` | O | With a valid session, returns an empty account list while no proof is active and one Sui zkLogin account while a valid proof is active. |
| Display feedback | O | Shows the rotary dial and center passcode slots for local-authentication input. |
| Touch feedback | O | Rotary telephone-style digit pull/release appends digits into four fixed center slots. |
| Physical button feedback | O | KEYA deletes local-authentication input. KEYB submits or confirms local-authentication input. KEYA+KEYB remains local feedback only. |
| Vibration feedback | O | Target-local user feedback only; it does not authorize protocol behavior. |
| Power-button behavior | O | USB-power-present short click toggles display backlight off/on. USB-power-absent short click remains the StopWatch PMIC power-on/reset behavior. Hardware double-click power-off remains PMIC-owned. |
| zkLogin proof storage | O | Stores one current-format Sui zkLogin proof record with the Ed25519 seed prepared in the same credential session. Invalid or unreadable proof storage projects `error` and fails closed. |
| Firmware-local zkLogin proof verification | X | This ESP32-S3 target does not run the Sui zkLogin proof verifier locally. zkLogin correctness is verified outside Firmware by checking normal zkLogin signatures with the Sui verifier. |
| zkLogin credential reset | O | StopWatch has no separate proof-clear action. The active zkLogin credential is removed only by Device reset, which also clears local authentication and mutable settings. There is no protocol proof-clear method. |
| Credential preparation/proposal | O | `credential_prepare` creates session-bound Ed25519 public material for zkLogin proof issuance. `credential_propose` consumes a payload-backed current Sui zkLogin proof shape, shows device-local review, requires local authentication, and activates the proof on successful commit. The session ends after activation. |
| Payload transfer | O | Implements the shared `payload_transfer` begin/chunk/finish/abort operation for credential proposal payload input with session binding, digest validation, timeout, abort, and scratch cleanup. |
| Signing | O | User-confirmed Sui `sign_personal_message`; user-confirmed or policy-authorized Sui `sign_transaction` according to the stored signing authorization mode. |
| Signing authorization mode | O | Device-local idle-screen mode selection. KEYA opens the mode screen, KEYB selects the opposite mode, and local-authentication confirmation stores it. |
| Policy | O | Stores the current policy document, returns it through `policy_get`, applies `policy_propose` after device-local policy review and local-authentication confirmation, and authorizes or rejects policy-mode Sui transaction signing through the current policy. |
| Approval history | O | Records policy-update and signing-decision history and exposes it through `get_approval_history`. |
| Retained responses | O | Implemented for successful signing responses within the active session. |

## State Model

The current target has no mnemonic or native root-material wallet path. It has
target-local local-authentication state, neutral idle after successful local
authentication, volatile protocol session state, payload-transfer scratch, and
one target-local Sui zkLogin credential record.

Status projection:

- before local authentication setup completes: `provisioning.state =
  "unprovisioned"` and `device.state = "idle"`;
- after local authentication setup completes and while locked:
  `provisioning.state = "unprovisioned"` and `device.state = "locked"`;
- after local authentication setup completes and while locally unlocked with no
  pending work: `provisioning.state = "unprovisioned"` and `device.state =
  "idle"`;
- after a valid Sui zkLogin credential is active and while locally unlocked with
  no pending work: `provisioning.state = "provisioned"` and `device.state =
  "idle"`;
- while connect approval, proof review, proof authentication, Device reset, or
  another request overlay is visible: `device.state = "busy"`;
- if the local-authentication record is invalid or storage cannot be read:
  `provisioning.state = "error"` and `device.state = "error"`.
- if the local-authentication record is missing while any zkLogin credential or
  mutable settings record remains, the stored material set is inconsistent:
  `provisioning.state = "error"` and `device.state = "error"`.
- if the zkLogin credential record is invalid or storage cannot be read:
  `provisioning.state = "error"` and `device.state = "error"`.
- after local authentication setup completes, if the current policy document or
  signing authorization mode is missing, invalid, or unreadable:
  `provisioning.state = "error"` and `device.state = "error"`.

`get_status` is allowed in every state. Successful local authentication shows a
neutral idle screen with a centered `IDLE` label. USB `connect` is the only
protocol path that creates a session, and it creates one only after
device-local approval when no session already exists and the current policy
document and signing authorization mode are both active. `credential_propose`
is the only protocol path that installs an active Sui zkLogin credential, and
it requires a valid session, the session's credential preparation, a
payload-backed current proof shape, device-local proof review, and local
authentication.

Signing scratch and retained-response state exists for active Sui signing
requests and retained signed results. Policy storage, policy-update scratch,
signing authorization mode storage, and approval history exist in this target.
The stored signing authorization mode is initialized to user mode during first
setup. From the idle screen, KEYA opens local signing mode selection; KEYB
chooses the opposite mode; storing the new mode requires local-authentication
confirmation. The host cannot choose the mode. In policy mode,
`sign_personal_message` fails with `unsupported_method`. `sign_transaction`
evaluates the current policy and either returns a policy rejection or returns a
zkLogin transaction signature with `authorization = "policy"`.

## Local Authentication

The local-authentication UI uses a rotary telephone-style touch dial:

- touch a digit on the outer dial;
- pull it toward the dial stop;
- release after the acceptance threshold to append the digit;
- the digit ring visibly rotates during the pull and returns to rest after
  release;
- entered digits appear in the center fixed-width slots during
  local-authentication input, then change to `*` after a short delay;
- press KEYB to submit or confirm;
- press KEYA to delete a digit.

The passcode is a decimal sequence with a user-selected length from 1 to 4
digits in the current four-slot layout. Short memorable values are allowed.
The security control is persistent
anti-hammering: five failed attempts enter time lock, and later failures raise
the persistent lock tier. Powered-off time does not reduce a lock because this
target does not use a trusted wall-clock source for local-authentication
lockout.

The stored local-authentication record contains a current-format salted verifier,
failed-attempt count, lock tier, and lock duration. Firmware re-anchors the
current boot's lock deadline from the stored duration when it starts. It does not
store raw passcode input.

If the local-authentication record is missing while any zkLogin credential or
mutable settings record remains, or if the local-authentication record is
invalid or storage cannot be read, the device fails closed. KEYB performs
Device reset because local authentication cannot be verified. Device reset
clears local authentication, the active zkLogin credential, mutable settings,
session state, pending state, retained responses, and signing scratch, then
returns to first-run setup.

## Sessions And zkLogin Proof Bootstrap

`connect` accepts the shared `{ clientName }` payload. When local
authentication is active and unlocked and no session exists, the request enters
a device-local `LINK?` approval overlay. KEYB approves and creates a new
volatile session; KEYA rejects with `user_rejected`. While a session is live on
the same USB link, another `connect` request returns the existing session
without another approval. This same-link recovery preserves long-running host
connections and does not create or replace a session.

`credential_prepare` is available only with a valid session while no zkLogin
proof is active. It creates session-bound Ed25519 preparation key material and
returns only public material through the shared response shape.

`payload_transfer` is available only with a valid session and local
authentication unlocked. It is used to deliver the bounded proof payload for
`credential_propose`. The target validates transfer ids, payload refs,
canonical base64 chunks, declared size, digest, timeout, and abort semantics
through the shared payload-transfer protocol rules.

`credential_propose` is available only with a valid session, the session's
credential preparation, and no active proof. It validates the current Sui
zkLogin credential payload shape, resolves the payload reference, shows a
device-local `PROOF?` review, requires local-authentication confirmation, then
stores the proof record and the session's prepared seed on successful commit.
Successful activation ends the session. Rejection, timeout, UI error, storage
error, or consistency error returns the shared credential proposal outcome and
performs the matching cleanup.

This ESP32-S3 target does not perform Firmware-local Sui zkLogin proof
verification. The target treats that verifier as outside its practical compute
and dependency budget. The verification boundary for this target is normal
zkLogin signing checked by the external Sui verifier, not local proof
verification by Firmware.

KEYB on the idle screen opens a device-local Device reset review. Confirming it
requires local authentication and clears local authentication, the active
zkLogin credential, mutable settings, session state, pending state, retained
responses, and signing scratch. Device reset is not a protocol method and
cannot be triggered by the host.

## USB Request Handling

The current USB transport accepts newline-delimited JSON requests over ESP32-S3
USB Serial/JTAG.

Implemented request behavior:

- malformed JSON fails with `invalid_request`;
- missing or unsafe `id`, missing `method`, or missing `version` fails with
  `invalid_request`;
- unsupported protocol version fails with `unsupported_version`;
- unsupported method fails with `unsupported_method`;
- `get_status` accepts only `id`, `version`, and `method`;
- `get_status` with extra fields fails with `invalid_request`;
- `identify_device`, `connect`, `disconnect`, `get_capabilities`,
  `get_accounts`, `credential_prepare`, and `credential_propose` implement the
  shared method rows described above;
- `payload_transfer` implements the shared transport operation described above;
- `policy_get` requires an active session and returns the current policy
  document;
- `policy_propose` requires an active session, validates the shared policy
  proposal payload, shows a device-local policy review, requires
  local-authentication confirmation, writes the current policy on approval, and
  records the policy-update history result;
- `get_approval_history` requires an active session and returns policy-update
  and signing-decision history records;
- `sign_transaction` requires an active session, an active Sui zkLogin account,
  matching network, canonical base64 transaction bytes, no conflicting
  sensitive payload-transfer state, transaction classification through the
  shared Sui transaction parser, and successful zkLogin signature envelope
  construction. In user mode, it requires device-local user approval.
  Clear-signing review shows parsed transaction summary fields; blind signing
  is labeled as blind signing before approval. In policy mode, it evaluates the
  current policy from Firmware storage and either returns `policy_rejected` or a
  retained signed result with `authorization = "policy"`;
- `sign_personal_message` requires an active session, an active Sui zkLogin
  account, matching network, canonical base64 message bytes, no conflicting
  sensitive payload-transfer state, user-mode signing authorization,
  device-local user approval, and successful zkLogin signature envelope
  construction. In policy mode it fails with `unsupported_method`;
- `get_result` and `ack_result` validate the retained-response payload shape and
  return or acknowledge a retained signing response for the current session;
  otherwise they fail with `unknown_request`.

The target does not implement a test-only setup path, debug state setter,
provisioning shortcut, or host-triggered reset.

## Power Button Behavior

Power-button behavior is target-local hardware UX:

- while USB power is present, short M5PM1 power-button click turns the display
  backlight off when it is on and restores the display backlight when it is off;
- while the display is off in USB-power-present mode, KEYA, KEYB, KEYA+KEYB,
  touch input, and request feedback restore the display before updating the
  screen;
- USB request handling continues while the display is off in USB-power-present
  mode;
- while USB power is absent, short M5PM1 power-button click remains the
  StopWatch PMIC power-on/reset behavior;
- hardware power-off remains the StopWatch PMIC double-click behavior and is
  not implemented as a Firmware protocol command or app-owned state transition.

This behavior does not expose a protocol command, does not change public
provisioning state or device state, and does not authorize or reject protocol
requests.

## Hardware Boundary

Display, touch, physical buttons, vibration, power behavior, and USB transport
are target-local. They must not become the source of truth for product state,
signing state, policy state, session state, or sensitive scratch cleanup.
