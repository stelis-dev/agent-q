# StopWatch ESP32-S3 Firmware Target

This directory contains the StopWatch ESP32-S3 hardware-specific Firmware
source overlay.

Current status: the target implements the local-authentication base slice, the
Sui zkLogin proof-bootstrap slice, and the Sui signing/policy slice:

- USB Serial/JTAG newline-delimited JSON transport;
- `get_status` with shared status projection for first-run setup,
  local-authentication lock, neutral idle, active zkLogin proof, and error
  states;
- rotary telephone-style touch PIN setup and unlock with a one-to-four-digit
  policy, four slots, and a visible rotating digit ring on the round display;
- a PIN-wrapped random master key, authenticated encrypted zkLogin credential
  and local-transport identity records, and separate non-secret persistent
  failed-attempt and time-lock metadata;
- neutral idle with a centered `IDLE` label after successful local
  authentication;
- USB `connect` approval, Firmware sessions, same-link session recovery,
  `disconnect`, `get_capabilities`, and `get_accounts`;
- a target-local QR scene and BLE peripheral that use the shared optical
  payload, Noise XX, encrypted-frame, pairing-state, and protocol-dispatch
  owners; KEYA enters from unlocked idle and cancels the pairing window. A USB
  data link blocks entry and closes an existing BLE carrier without migrating
  its session or response route;
- `credential_prepare`, `payload_transfer`, and `credential_propose` for
  installing a Sui zkLogin proof after device-local review and local
  authentication;
- device-local Device reset from the idle screen. Device reset also resets the
  StopWatch zkLogin credential and returns the device to first-run
  local-authentication setup;
- user-confirmed Sui `sign_personal_message` and user-confirmed or
  policy-authorized Sui `sign_transaction` for an active zkLogin account,
  including retained response lookup and acknowledgement for signed results;
- current policy storage, `policy_get`, device-confirmed `policy_propose`, and
  approval-history records for policy updates and signing decisions;
- device-local signing authorization mode selection after local authentication;
- shared failure responses for methods that are unavailable in this target
  state or slice;
- local display, touch, physical button, and vibration feedback used by this
  slice;
- target-local power-button behavior: while USB power is present, short press
  toggles display backlight off/on; while USB power is absent, short press
  remains the StopWatch PMIC power-on/reset behavior; hardware double-click
  power-off remains PMIC-owned. While the display is off, the M5PM1 power
  button, KEYA, and KEYB wake it and consume that first physical input. Touch
  does not wake the display or enter a dial digit.

The target does not implement a camera, host-triggered reset, Firmware-local
Sui zkLogin proof verification, or a mnemonic/native root-material wallet path.

Target-specific behavior and capability status live in `SPEC.md`.

## Build

Install ESP-IDF `v5.5.4`, then run:

```bash
FIRMWARE_IDF_PATH=/path/to/esp-idf-v5.5.4 \
  firmware/tools/stopwatch-esp32s3/with-idf.sh \
  firmware/tools/stopwatch-esp32s3/build.sh
```

The default checkout path is:

```text
.firmware-cache/stopwatch-esp32s3/M5StopWatch-UserDemo
```

The default build directory is:

```text
.firmware-cache/stopwatch-esp32s3/M5StopWatch-UserDemo/build-stopwatch-esp32s3
```

The build shell fetches the pinned official M5Stack StopWatch ESP-IDF host
project and pinned Git component dependencies into `.firmware-cache/`, applies
the tracked overlay from `firmware/src/stopwatch-esp32s3/overlay/main/`, and
builds the generated ESP-IDF project. Tracked build scripts do not use `.WORK/`
as a build input.

## Flash

The current encrypted-keystore layout has no compatibility reader or migration
from an earlier StopWatch storage layout. Before flashing it over an older
development image, erase the whole flash and complete device-local setup again.
Do not use a normal flash as an upgrade path from an older layout.

After building, flash with ESP-IDF against the generated checkout and build
directory:

```bash
FIRMWARE_IDF_PATH=/path/to/esp-idf-v5.5.4 \
  firmware/tools/stopwatch-esp32s3/with-idf.sh \
  idf.py \
    -C .firmware-cache/stopwatch-esp32s3/M5StopWatch-UserDemo \
    -B .firmware-cache/stopwatch-esp32s3/M5StopWatch-UserDemo/build-stopwatch-esp32s3 \
    -p /dev/cu.usbmodemXXXX \
    erase-flash

FIRMWARE_IDF_PATH=/path/to/esp-idf-v5.5.4 \
  firmware/tools/stopwatch-esp32s3/with-idf.sh \
  idf.py \
    -C .firmware-cache/stopwatch-esp32s3/M5StopWatch-UserDemo \
    -B .firmware-cache/stopwatch-esp32s3/M5StopWatch-UserDemo/build-stopwatch-esp32s3 \
    -p /dev/cu.usbmodemXXXX \
    flash
```

## Hardware

- Product: M5Stack StopWatch / M5Stack StopWatch Dev Kit (ESP32-S3).
- SoC: ESP32-S3R8.
- Display: 1.75-inch round AMOLED, 466x466 visible resolution, CO5300, QSPI.
- Touch: CST820B.
- Buttons: KEYA on G2, KEYB on G1, plus M5PM1 power button.
- Vibration: built-in motor through M5IOE1 PWM.
- Power: M5PM1, 450mAh battery, USB Type-C 5V input.

Power-button behavior is target-local. While USB power is present, a short M5PM1
power-button press toggles the display backlight off and on. While the display
is off, the M5PM1 power button, KEYA, KEYB, or the KEYA+KEYB chord turns it back
on and consumes that physical input before its normal action. Touch does not
wake the display and cannot enter a dial digit until a physical or
Firmware-request wake has completed and the touch surface has been released.
Firmware-owned identification and request UI may still wake the display so a
pending review is visible. While USB power is absent, a short power-button
press remains the StopWatch PMIC power-on/reset behavior. Hardware power-off
remains the StopWatch PMIC double-click behavior and is not implemented as a
Firmware protocol method or app-owned product state transition.

## Boundary

This target keeps display, touch, buttons, vibration, power behavior, physical
USB integration, BLE memory buffers, encrypted-record composition and storage
names, the measured fixed KDF profile, QR composition, credential shape,
proposal state, reset composition, and hardware glue target-local. The
encrypted-keystore process, NVS storage operations, callback-scoped identity
store, BLE peripheral, encrypted carrier, and pairing state process are shared
Firmware owners.
Protocol method and error rows are shared through
`firmware/src/common/protocol/device_contract.{h,cpp}`. Protocol version,
request-id validation, JSON input helpers, USB request line framing, session id
grammar, payload-transfer protocol primitives, and Sui zkLogin credential DTO
validation are shared through `firmware/src/common/` because they are product
protocol invariants, not StopWatch-specific hardware behavior. Further common
extraction is allowed only when it preserves a tested current product invariant
or after completed target slices prove the same source contract and owner
boundary.
