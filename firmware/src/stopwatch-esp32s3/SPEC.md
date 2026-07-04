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
  local-authentication base slice;
- report shared status projection through `get_status`;
- provide shared failure responses for methods that are unavailable in this base
  slice;
- provide local display, touch, physical button, and vibration feedback for this
  slice;
- provide target-local power-button behavior.

It is not a signing-ready target. It does not expose MCP directly and does not
provide chain-specific signing APIs.

## Target Status

Legend:

- `O`: implemented for this target.
- `X`: not implemented for this target.
- `N/A`: not applicable to this target.

| Capability | Status | Notes |
|---|---:|---|
| USB JSONL transport | O | Uses ESP32-S3 USB Serial/JTAG. |
| `get_status` | O | Reports shared status projection for first-run setup, local-authentication lock, blank idle, and local-authentication error states. |
| Local authentication setup | O | User creates a 1-to-4 digit rotary telephone-style passcode on the round display and repeats it before storage. |
| Local authentication verification | O | Stores a salted verifier, failed-attempt count, lock tier, and lock duration. Raw passcode input is not stored. |
| Local authentication recovery | O | If the current local-authentication record is invalid or unreadable, the device fails closed. KEYB clears only the local-authentication record and returns to first-run setup. No signing material exists in this slice. |
| `connect` | X | Not implemented in this base slice; parseable requests fail closed with `invalid_state`. |
| Firmware sessions | X | Not implemented. |
| `disconnect` session cleanup | X | Not implemented. |
| `get_capabilities` | X | Not implemented. |
| `get_accounts` | X | Not implemented. |
| Display feedback | O | Shows the rotary dial and center passcode slots for local-authentication input. |
| Touch feedback | O | Rotary telephone-style digit pull/release appends digits into four fixed center slots. |
| Physical button feedback | O | KEYA deletes local-authentication input. KEYB submits or confirms local-authentication input. KEYA+KEYB remains local feedback only. |
| Vibration feedback | O | Target-local user feedback only; it does not authorize protocol behavior. |
| Power-button behavior | O | USB-power-present short click toggles display backlight off/on. USB-power-absent short click remains the StopWatch PMIC power-on/reset behavior. Hardware double-click power-off remains PMIC-owned. |
| zkLogin proof storage | X | Not implemented. |
| Payload transfer | X | Not implemented. |
| Signing | X | Not implemented. |
| Policy | X | Not implemented. |
| Approval history | X | Not implemented. |
| Retained responses | X | Not implemented. |

## State Model

The current target has no persistent signing material and no active zkLogin
proof flow. It has target-local local-authentication state and blank idle after
successful local authentication. It has no protocol session state.

Status projection:

- before local authentication setup completes: `provisioning.state =
  "unprovisioned"` and `device.state = "idle"`;
- after local authentication setup completes and while locked:
  `provisioning.state = "unprovisioned"` and `device.state = "locked"`;
- after local authentication setup completes and while locally unlocked with no
  pending work: `provisioning.state = "unprovisioned"` and `device.state =
  "idle"`;
- if the local-authentication record is invalid or storage cannot be read:
  `provisioning.state = "error"` and `device.state = "error"`.

`get_status` is allowed in every state. Successful local authentication shows a
blank idle screen. USB `connect`, `disconnect`, `get_capabilities`,
`get_accounts`, credential methods, payload transfer, policy, signing, retained
responses, and approval history do not create sessions and do not change target
state in this base slice.

No signing scratch, policy state, account state, approval-history state,
retained-response state, payload-transfer state, or zkLogin proof state exists
in this target.

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

If the local-authentication record is invalid or storage cannot be read, the
device fails closed. KEYB clears the local-authentication record and returns to
first-run setup.
This recovery does not erase signing material because this slice does not store
signing material.

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
- `get_status` with extra fields fails with `invalid_params`;
- every other shared method that is parseable enough to identify fails with
  `invalid_state` in this base slice, including `identify_device`, `connect`,
  `disconnect`, `get_capabilities`, `get_accounts`, `policy_get`,
  `policy_propose`, `credential_prepare`, `credential_propose`,
  `get_approval_history`, `get_result`, `ack_result`, `sign_transaction`, and
  `sign_personal_message`.

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
