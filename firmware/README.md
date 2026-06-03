# Agent-Q Firmware

Agent-Q Firmware is the program installed on a hardware device.

Firmware is the signing authority. It stores keys and policies, evaluates
requests, and handles device-local approval according to target policy. Current
public methods expose account, session, policy, approval-history, and policy
proposal behavior. Public signing methods are not implemented.

## Folder Policy

### `src/common/`

Hardware-independent firmware source shared by targets.

Common source may include protocol parsers, chain transaction decoders, pure
data-format helpers, and test fixtures when they do not depend on a hardware
runtime. Common modules must not include target UI, USB transport, NVS layout,
display power, posture, or other hardware-specific integration code.

### `src/<hardware-id>/`

Hardware-specific firmware source roots.

Each supported hardware device gets one direct child directory under `src/`,
next to `common/`. Do not pre-create deep subfolders before implementation needs
them.

Example:

```text
src/
  common/
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

Shared firmware dependency pins live in `firmware/source.env`.
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
AGENT_Q_IDF_PATH=/path/to/esp-idf-v5.5.4 \
  firmware/tools/stackchan-cores3/with-idf.sh \
  firmware/tools/stackchan-cores3/build.sh
```

Use the `with-idf.sh` launcher for local ESP-IDF commands. It activates ESP-IDF
with Python 3.11 by default so one build directory is not shared by different
ESP-IDF Python virtual environments. Checks that do not require ESP-IDF can be
run directly, while ESP-IDF-dependent target checks should be passed through the
same launcher.

```bash
firmware/tools/common/generate_sui_transaction_fixtures.mjs
firmware/tools/common/test_sui_transaction_facts.sh
firmware/tools/common/test_policy_v0.sh
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
