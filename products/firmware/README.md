# Agent-Q Firmware

Agent-Q Firmware is the program installed on a hardware device.

Firmware is the signing authority. It stores keys and policies, evaluates
signing requests, asks for physical approval when required, and returns
signatures or rejections to Agent-Q Gateway.

## Folder Policy

### `src/`

Hardware-specific firmware source roots.

Each supported hardware device gets one direct child directory under `src/`.
Do not pre-create deep subfolders before implementation needs them.

Example:

```text
src/
  stackchan-cores3/
```

### `build/`

Firmware build artifacts.

Build output should be copied here for installation, flashing, release checks,
or manual testing. Source code should not live in this directory.

## Protocol

Firmware implementations follow the shared Agent-Q communication protocol in
`specs/PROTOCOL.md`.
