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
  first slice;
- report unprovisioned status through `get_status`;
- reject `connect` while unprovisioned with the current protocol
  `invalid_state` error;
- provide local display, touch, physical button, battery display, and vibration
  feedback for the first slice.

It is not a signing product target. It does not expose MCP directly and does
not provide chain-specific signing APIs.

## Target Status

Legend:

- `O`: implemented for this target.
- `X`: not implemented for this target.
- `N/A`: not applicable to this target.

| Capability | Status | Notes |
|---|---:|---|
| USB JSONL transport | O | Uses ESP32-S3 USB Serial/JTAG. |
| `get_status` | O | Reports unprovisioned target status. No material consistency refresh exists because this target stores no signing material. |
| `connect` | O | Fails closed with `invalid_state` while unprovisioned. No session is created. |
| Display feedback | O | Shows first-slice status, USB counters, last input, battery level, and charging state. |
| Touch feedback | O | Touch A and Touch B update local UI state and trigger vibration. |
| Physical button feedback | O | KEYA, KEYB, and KEYA+KEYB events update local UI state and trigger vibration. |
| Vibration feedback | O | Target-local user feedback only; it does not authorize protocol behavior. |
| Provisioning | X | Not implemented. |
| Approved connect | X | Not implemented. |
| Firmware sessions | X | Not implemented. |
| `disconnect` session cleanup | X | Not implemented. |
| Signing | X | Not implemented. |
| Policy | X | Not implemented. |
| Accounts | X | Not implemented. |
| zkLogin | X | Not implemented. |
| Approval history | X | Not implemented. |
| Retained responses | X | Not implemented. |

## State Model

The current target has no persistent signing material and no provisioning flow.
It reports:

- provisioning state: `unprovisioned`;
- device state: `idle`, except transient display updates that do not change
  product authority.

`get_status` is allowed. `connect` is unavailable and fails closed with
`invalid_state` before provisioned-only payload details matter. No device-local
approval state, session state, signing scratch, policy state, account state, or
approval-history state exists in this target.

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
- `connect` fails with `invalid_state` while unprovisioned.

The target does not implement a test-only setup path, debug state setter,
provisioning shortcut, or host-triggered reset.

## Hardware Boundary

Display, touch, physical buttons, vibration, battery display, power behavior,
and USB transport are target-local. They must not become the source of truth for
product state, signing state, policy state, session state, or sensitive scratch
cleanup.
