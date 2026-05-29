# StackChan CoreS3 Firmware Source

This directory contains the first hardware-specific Agent-Q firmware source
overlay.

Target-specific behavior and capability status live in `SPEC.md`.

The current implementation includes:

- a boot-time signing self-test that proves the firmware can link the signing
  dependency, create an Ed25519 Sui-formatted signature from a runtime-generated
  test seed, verify that signature on the device, and log the result without
  showing boot UI.
- a USB JSONL request/response smoke path for `display_signal`. It proves that a
  local process can send a request over USB, the device can show an on-screen
  YES/NO prompt, and the device can return the selected JSON response only after
  physical touch input.
- a USB JSONL `get_status` request that follows the shared protocol envelope and
  returns a persistent device id plus the current device state without showing a
  physical approval UI.
- a USB JSONL `identify_device` request that shows a short temporary code over
  the current screen and then returns to the previous device state.
- a USB JSONL `connect` request that shows a physical approval prompt with the
  Gateway display name and, on YES, returns a Firmware-generated session id with
  a Firmware-owned TTL. NO or timeout returns `rejected`. The request replaces
  any previously active Firmware session only after physical YES.
- a USB JSONL `disconnect` request that clears the active Firmware session when
  the supplied session id matches.
- a locked-down Agent-Q firmware profile that keeps only the local launcher,
  local default avatar idle surface, and USB Agent-Q request server. It does not
  start the StackChan/Xiaozhi remote AI runtime, does not register Xiaozhi MCP
  tools, does not initialize the camera, does not start the setup/login worker,
  ignores Xiaozhi vision capabilities, and disables the remote WebSocket avatar
  service.
- an Agent-Q-only avatar UI layer. The StackChan default avatar face stays
  visible, the upstream default speech bubble is hidden by default, and Agent-Q
  requests use an Agent-Q-owned speech-bubble decorator with state-specific
  colors plus a small confirmation strip when physical input is required.

Sessions live in RAM. Firmware reboot clears the active session. Session ids
are derived from device RNG and are not derived from MAC address, USB serial
number, `deviceId`, account public key, or signing key. Sessions do not
authorize signing.

This is not the signing product yet. It does not persist keys, store policies,
parse signable transactions, expose MCP directly, or apply signing policy. The
only persisted value in this target implementation is the protocol `deviceId`
used by Gateway for reconnect hints.

Agent-Q firmware is intentionally not a general StackChan AI firmware. It does
not include StackChan World login, Xiaozhi cloud sessions, camera upload, screen
snapshot upload, remote video, app center, setup, EzData, or other non-Agent-Q
remote surfaces. Developers who need those upstream StackChan features should
flash the upstream firmware separately and must not treat that firmware as an
Agent-Q signing device.

## Source And Build

This directory is an Agent-Q overlay for the upstream StackChan firmware host
tree. It is not a complete standalone ESP-IDF project.

The pinned upstream host source and ESP-IDF version live in this directory's
`source.env`. Shared firmware dependency pins live in
`products/firmware/source.env`. Tracked tools use those files so local builds
and GitHub Actions use the same inputs:

```bash
source /path/to/esp-idf-v5.5.4/export.sh
tools/firmware/stackchan-cores3/build.sh
```

The build script downloads the pinned upstream firmware and signing-source
checkouts into `.firmware-cache/` when needed, copies this overlay into the
firmware checkout, and builds. It does not require `.WORK/`. A developer may
still use `.WORK/` as a local investigation cache, but that cache is not source
of truth and is not used by CI.

During preparation, the tracked build tools also patch the pinned upstream host
tree so the Agent-Q build does not start the StackChan/Xiaozhi remote AI
runtime, does not register Xiaozhi remote MCP tools, does not initialize the
camera, and does not start remote avatar WebSocket service.

## Current Integration Points

In the hardware firmware tree:

- Add `agent_q/*.cpp` to the main firmware component sources.
- Add the `signing_crypto` component to the main firmware component
  dependencies.
- Add `esp_driver_usb_serial_jtag` to the main firmware component dependencies
  for the USB JSONL smoke path.
- Call `agent_q::run_signing_self_test()` once during boot after hardware
  initialization.
- Initialize NVS during the host firmware boot sequence before Agent-Q
  initialization.
- Call `agent_q::init_usb_request_server()` once after boot checks and NVS
  initialization.
- `agent_q::init_usb_request_server()` starts the USB request task. The task
  keeps protocol handling available even when another firmware mode takes over
  the main app loop.

## Persistent Storage

This target stores the protocol `deviceId` in NVS namespace `agent_q` with key
`device_id`.

Agent-Q-owned modules are sources under `agent_q/` in this target tree. These
modules may share the `agent_q` namespace. New keys should be named by feature,
such as `<feature>_<name>`, to avoid collisions.
