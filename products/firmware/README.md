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

## Build Policy

Firmware build and CI paths must start from tracked repository files, not from a
developer's `.WORK/` checkout.

Shared firmware dependency pins live in `products/firmware/source.env`.
Hardware-specific targets that require an upstream host firmware tree must keep
that dependency pinned under `src/<hardware-id>/source.env`. The build flow is:

```text
fetch pinned upstream host firmware
  -> apply tracked Agent-Q hardware overlay
  -> fetch pinned signing source
  -> build
```

Tracked build scripts download firmware build dependencies into
`.firmware-cache/`. Local developers may keep ESP-IDF installs or
investigation-only source checkouts under `.WORK/`, but `.WORK/` paths must not
appear in user-facing build commands or GitHub workflows.

For the current StackChan CoreS3 target:

```bash
source /path/to/esp-idf-v5.5.4/export.sh
tools/firmware/stackchan-cores3/build.sh
```

The build script downloads the pinned host firmware and signing source into the
ignored `.firmware-cache/` directory when needed, applies the tracked hardware
overlay, and then builds. `AGENT_Q_SIGNING_CRYPTO_ROOT` may be used to point at
a different local signing-source checkout for investigation, but the default
tracked build path uses the pinned cache. GitHub Actions uses the same tracked
script.

## Common Firmware UX Policy

These rules apply to every hardware-specific Firmware implementation.

Firmware must not force the device into a dedicated Agent-Q mode for normal
requests. The device should keep its current mode, app, screen, or idle state
running whenever possible.

Request UI should be temporary:

- normal boot must not show Agent-Q installation or self-test popups;
- read-only status and discovery requests must not show physical approval UI;
- device identification may show a short temporary code, then return to the
  previous state;
- automatic approvals may show brief result feedback, then return to the
  previous state;
- requests that require physical approval must show an approval layer over the
  current state, wait for approve, reject, or timeout, send the result, show
  brief result feedback when useful, and remove the layer;
- timeout is a rejection result;
- hardware-specific input controls must map back to the shared outcomes:
  approve, reject, or timeout.

The expected lifecycle is:

```text
current device state
  -> request received
  -> policy decision
     -> auto approve: brief result feedback
     -> needs approval: approval layer
     -> reject: brief result feedback when useful
  -> response sent
  -> previous device state continues
```

Firmware may use hardware-specific rendering and controls, but the product
behavior must remain the same across hardware targets.
