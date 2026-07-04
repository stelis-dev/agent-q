# StopWatch ESP32-S3 Firmware Target

This directory contains the StopWatch ESP32-S3 hardware-specific Firmware
source overlay.

Current status: the target implements the local-authentication base slice:

- USB Serial/JTAG newline-delimited JSON transport;
- `get_status` with shared status projection for first-run setup,
  local-authentication lock, blank idle, and local-authentication error states;
- rotary telephone-style touch passcode setup and unlock with the current
  four-slot layout and a visible rotating digit ring on the round display;
- persistent local-authentication verifier with persistent failed-attempt count
  and time lock;
- blank idle after successful local authentication;
- shared failure responses for methods that are unavailable in this base slice;
- local display, touch, physical button, and vibration feedback used by this
  slice;
- target-local power-button behavior: while USB power is present, short press
  toggles display backlight off/on; while USB power is absent, short press
  remains the StopWatch PMIC power-on/reset behavior; hardware double-click
  power-off remains PMIC-owned.

The target does not implement USB connect approval, protocol sessions,
`disconnect` session cleanup, `get_capabilities`, `get_accounts`, zkLogin proof
storage, proof proposal review, signing, policy, approval history, retained
responses, payload transfer, or persistent signing material.

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

After building, flash with ESP-IDF against the generated checkout and build
directory:

```bash
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
is off, local input and request feedback turn it back on before updating the
screen. While USB power is absent, a short press remains the StopWatch PMIC
power-on/reset behavior. Hardware power-off remains the StopWatch PMIC
double-click behavior and is not implemented as a Firmware protocol method or
app-owned product state transition.

## Boundary

This target keeps display, touch, buttons, vibration, power behavior, USB
transport, and hardware glue target-local. Protocol method and error rows are
shared through `firmware/src/common/protocol/device_contract.{h,cpp}`.
Protocol version, request-id validation, JSON input helpers, and USB request
line framing are also shared through `firmware/src/common/protocol/`. Further
common extraction is allowed only after two completed target slices prove the
same source contract and owner boundary.
