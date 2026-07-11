# <Hardware Id> Firmware Target

This directory contains the `<Hardware Id>` hardware-specific Firmware source
overlay.

Current status: replace this paragraph with the exact implemented state. Do not
describe planned behavior as implemented.

Target-specific behavior and capability status live in `SPEC.md`.

## Build

Install the required SDK/toolchain, then run:

```bash
FIRMWARE_IDF_PATH=/path/to/esp-idf-vX.Y.Z \
  firmware/tools/<hardware-id>/with-idf.sh \
  firmware/tools/<hardware-id>/build.sh
```

The default checkout path is:

```text
.firmware-cache/<hardware-id>/<upstream-project>
```

The default build directory is:

```text
.firmware-cache/<hardware-id>/<upstream-project>/build-<hardware-id>
```

The build shell must fetch pinned dependencies into `.firmware-cache/`, apply
tracked source or overlay files, and build from tracked repository inputs. It
must not require `.WORK/` paths.

## Flash

After building, flash the generated build with the target SDK tools:

```bash
FIRMWARE_IDF_PATH=/path/to/esp-idf-vX.Y.Z \
  firmware/tools/<hardware-id>/with-idf.sh \
  idf.py \
    -C .firmware-cache/<hardware-id>/<upstream-project> \
    -B .firmware-cache/<hardware-id>/<upstream-project>/build-<hardware-id> \
    -p /dev/cu.usbmodemXXXX \
    flash
```

There must be no Agent-Q protocol command for flashing.

## Hardware

- Product:
- SoC:
- Display:
- Input:
- Buttons:
- Haptics:
- Power:
- Transport:

Hardware behavior is target-local. It must not create target-specific protocol
methods, schemas, public error codes, or product state transitions.

## Boundary

This target owns:

- board runtime integration;
- display rendering;
- input mapping;
- power behavior;
- transport adapter;
- storage adapter;
- identity adapter;
- signing-material adapter.

This target must use common modules for shared product contracts that it
implements:

- protocol envelope and method table;
- request id, session id, and shared error handling;
- payload-transfer primitives;
- policy parser/evaluator/store contracts when policy is implemented;
- account binding and signing route classification when signing is implemented;
- user-signing flow and signing critical section when user signing is
  implemented;
- approval-history record shape when approval history is implemented.

This target must not fork target-independent product state, transition order,
error precedence, scratch-wipe rules, or shared protocol schemas for the same
operation.

## Hardware Smoke Evidence

For each hardware smoke pass, record:

- target hardware;
- repository commit;
- build command;
- flash command;
- serial port;
- manual device-local steps;
- observed protocol result;
- observed UI result;
- unchecked paths.

Keep scratch evidence under `.WORK/notes/` or `.WORK/artifacts/`. Update tracked
status documents only when the verification level changes.
