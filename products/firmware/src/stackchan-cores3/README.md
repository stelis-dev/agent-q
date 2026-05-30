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
- protocol handling for `connect` and `disconnect`. The current target accepts
  `connect` only after material-backed `provisioned` state and physical
  approval. Firmware sessions are RAM-only and do not authorize signing.
- a USB JSONL `get_capabilities` request that returns Firmware-authored Sui
  Ed25519 account identity capability over an approved session while
  `provisioned`. The current `methods` list is empty because signing methods are
  not implemented.
- a USB JSONL `call_method` runtime skeleton. It requires material-backed
  `provisioned` state plus a matching active session, keeps unknown methods
  rejected with `unsupported_method`, and recognizes Sui `sign_transaction` only
  for restricted-transfer policy-decision smoke. It does not ask for signing
  approval or sign.
- USB JSONL mnemonic UI requests for `start_provisioning`,
  `cancel_provisioning`, and `confirm_recovery_phrase_backup`.
  `start_provisioning` generates DEV_PROFILE BIP-39 root entropy in RAM,
  displays only the up-to-4-letter word prefixes on device in a 3-column by
  4-row grid, and stores the root entropy only after physical backup
  confirmation. The local setup speech bubble starts the same flow on device,
  and the recovery phrase panel also has device-local Cancel/Confirm buttons.
- a USB JSONL `factory_reset` request that requires physical approval, clears
  RAM sessions and volatile setup scratch, erases the DEV_PROFILE root entropy
  blob, persists `unprovisioned`, and recovers from material/state consistency
  errors. This path is for DEV_PROFILE development and recovery; Gateway must
  not expose it as a normal agent-facing MCP tool.
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
- target-local display-power handling that turns the screen backlight off after
  three minutes of inactivity, wakes for Agent-Q request UI, toggles display power
  on side-button short press, and powers off on side-button long press. Before
  screen-off or power-off, the target moves to a rest posture; when the screen
  wakes, it returns to awake posture.
- StackChan-specific boot and sleep posture feedback that centers yaw and
  raises pitch after the default avatar is attached or the screen wakes, then
  moves to centered yaw and lowered pitch before screen-off or power-off.

Runtime Firmware sessions are implemented only as RAM-held protocol sessions
after material-backed provisioning. Sessions do not authorize signing.

This is not the signing product yet. It reports read-only identity capability
(`get_capabilities` with `methods: []`), derives only read-only public account
identity (`get_accounts`), and links a restricted host-tested Sui transaction
facts parser plus a common default-reject policy runtime boundary. The current
`call_method` skeleton consumes that default-reject decision only for Sui
`sign_transaction` policy-decision smoke; it does not sign, store policies,
expose MCP directly, or apply signing policy to produce signatures. The persisted values in this target implementation are the
protocol `deviceId`, provisioning state flag, and DEV_PROFILE root entropy blob
after backup confirmation.

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
tools/firmware/common/generate_sui_transaction_fixtures.mjs
tools/firmware/common/test_sui_transaction_facts.sh
tools/firmware/common/test_policy_v0.sh
tools/firmware/stackchan-cores3/test_bip39_vectors.sh
tools/firmware/stackchan-cores3/test_sui_account_vectors.sh
```

The build script downloads the pinned upstream firmware, signing-source, and
BIP-39 wordlist checkouts into `.firmware-cache/` when needed, copies this
overlay into the firmware checkout, generates the wordlist source, and builds.
It does not require `.WORK/`. A developer may still use `.WORK/` as a local
investigation cache, but that cache is not source of truth and is not used by
CI.

The BIP-39 vector test is a host-side check. It compiles the tracked
`agent_q_bip39.cpp` encoder with ESP-IDF mbedTLS SHA-256 sources and a
generated wordlist source from the pinned BIP-39 English wordlist.

The Sui account vector test is also host-side. It compiles the tracked
`agent_q_sui_account.cpp` derivation module with the pinned MicroSui signing
source and checks known Sui SDK address/public-key vectors.

The Sui transaction facts parser test is a common host-side check. It compiles
`products/firmware/src/common/agent_q/sui` and verifies tracked BCS fixtures for
the restricted SUI transfer parser. StackChan CoreS3 connects the parser only to
Sui `sign_transaction` policy-decision smoke; it is not signing.

The policy test is also a common host-side check. It compiles
`products/firmware/src/common/agent_q/policy` plus the Sui facts adapter and
verifies deny-by-default, `sign`/`reject`/`ask` decision calculation, default
provider behavior, missing/invalid policy provider rejection, malformed policy
rejection, and unsupported-facts rejection. StackChan CoreS3 consumes the
default-reject decision only for Sui `sign_transaction` policy-decision smoke;
policy is not connected to physical approval, capability advertisement, or
signing.

During preparation, the tracked build tools also patch the pinned upstream host
tree so the Agent-Q build does not start the StackChan/Xiaozhi remote AI
runtime, does not register Xiaozhi remote MCP tools, does not initialize the
camera, and does not start remote avatar WebSocket service.

## Current Integration Points

In the hardware firmware tree:

- Add `agent_q/*.cpp` to the main firmware component sources.
- Add `agent_q_common/sui/*.cpp` to the main firmware component sources for the
  shared hardware-independent Sui parser.
- Add `agent_q_common/policy/*.cpp` to the main firmware component sources for
  the shared hardware-independent policy evaluator.
- Add the `signing_crypto` component to the main firmware component
  dependencies.
- Add `mbedtls` to the main firmware component dependencies for BIP-39
  checksum generation.
- Add `bootloader_support` to seed the Agent-Q CSPRNG from early boot entropy
  before HAL initialization.
- Add `esp_driver_usb_serial_jtag` to the main firmware component dependencies
  for the USB JSONL smoke path.
- Call `agent_q::init_secure_random_from_early_boot_entropy()` before HAL
  initialization so recovery phrase generation never depends on late direct
  `esp_fill_random()` while RF/ADC entropy is unavailable.
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

This target stores the protocol `deviceId`, provisioning state, and DEV_PROFILE
root entropy in NVS namespace `agent_q`.

| Key | Purpose |
|---|---|
| `device_id` | Gateway reconnect and device-selection identity |
| `prov_state` | Provisioning state flag; `provisioned` is valid only with root entropy present |
| `root_entropy` | DEV_PROFILE BIP-39 root entropy blob; not exported over USB |

Recovery phrase setup v0 stores generated phrase text only in RAM, displays
only up-to-4-letter prefixes on device, and wipes the phrase on cancel, backup
confirmation, rejection, display expiry, timeout, or firmware restart.
Backup-confirmed root entropy is stored as DEV_PROFILE scaffolding only; this
build does not enable USER_PROFILE encrypted storage. Three-letter BIP-39 words
are displayed as the full word.

Agent-Q-owned modules are sources under `agent_q/` in this target tree. These
modules may share the `agent_q` namespace. New keys should be named by feature,
such as `<feature>_<name>`, to avoid collisions.
