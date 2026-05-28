# StackChan CoreS3 Firmware Source

This directory contains the first hardware-specific Agent-Q firmware source
overlay.

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

This is not the signing product yet. It does not persist keys, store policies,
parse signable transactions, expose MCP directly, or apply signing policy. The
only persisted value in this target implementation is the protocol `deviceId`
used by Gateway for reconnect hints.

## Current Integration Points

In the hardware firmware tree:

- Add `agent_q/*.cpp` to the main firmware component sources.
- Add the `signing_crypto` component to the main firmware component
  dependencies.
- Add `esp_driver_usb_serial_jtag` to the main firmware component dependencies
  for the USB JSONL smoke path.
- Call `agent_q::run_signing_self_test()` once during boot after hardware
  initialization.
- Call `agent_q::init_usb_request_mvp()` once after boot checks.
- `agent_q::init_usb_request_mvp()` starts the USB request task. The task keeps
  protocol handling available even when another firmware mode takes over the
  main app loop.
