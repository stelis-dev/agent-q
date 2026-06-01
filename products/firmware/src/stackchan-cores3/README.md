# StackChan CoreS3 Firmware Source

This directory contains the first hardware-specific Agent-Q firmware source
overlay.

Target-specific behavior and capability status live in `SPEC.md`.

The current implementation includes:

- a boot-time signing self-test that proves the firmware can link the signing
  dependency, create an Ed25519 Sui-formatted signature from a runtime-generated
  test seed, verify that signature on the device, and log the result without
  showing boot UI.
- a USB JSONL `get_status` request that follows the shared protocol envelope and
  returns a persistent device id plus the current device state without showing a
  physical approval UI.
- a USB JSONL `identify_device` request that shows a short temporary code over
  the current screen and then returns to the previous device state.
- protocol handling for `connect` and `disconnect`. The current target accepts
  `connect` only after material-backed `provisioned` state and device-local
  approval. By default that approval is stored-PIN entry on the device; a local
  settings toggle can switch connect approval to physical Confirm after PIN
  verification. Firmware sessions are RAM-only and do not authorize signing.
- a USB JSONL `get_capabilities` request that returns Firmware-authored Sui
  Ed25519 account identity capability over an approved session while
  `provisioned`. The current `methods` list is empty because signing methods are
  not implemented.
- a USB JSONL `get_approval_history` request that returns bounded persistent
  Firmware-authored method-decision metadata over an approved session. It is
  read-only, rate-limits persistent writes to reduce flash wear, stores no raw
  requests or secrets, and currently records only validated `call_method`
  policy-rejected decisions.
- a USB JSONL `call_method` runtime skeleton. It requires material-backed
  `provisioned` state plus a matching active session, keeps unknown methods
  rejected with `unsupported_method`, and recognizes Sui `sign_transaction` only
  for restricted-transfer policy-decision smoke. It does not ask for signing
  approval or sign.
- a device-local mnemonic setup flow. The local setup speech bubble opens a
  Generate/Recover choice. Generate creates DEV_PROFILE BIP-39 root entropy in
  RAM, displays only the up-to-4-letter word prefixes on device in a 3-column
  by 4-row grid, and advances to local 6-digit PIN entry after the recovery
  phrase panel's local `Confirm` button. Recover accepts 12 BIP-39 words
  through a device-local 3-word-per-page prefix/candidate UI, verifies checksum,
  and then advances to the same local PIN setup path. The target stores the root
  entropy plus active default-reject policy plus salt/PIN verifier only after
  the repeated PIN matches. Local Cancel controls wipe volatile setup scratch.
  These setup transitions are not exposed as USB JSONL requests.
- device-local settings flows for `provisioned` devices. Change PIN verifies the
  current stored 6-digit PIN, accepts and repeats a new PIN, and replaces only
  the salt/PIN verifier. Reset requires the local Settings Reset action plus
  the stored PIN, wipes root material, active policy, PIN verifier,
  approval history, connect-approval setting, runtime session, and provisioning
  state, and is not exposed as a USB JSONL request. StackChan CoreS3 local reset
  was manually smoke-tested after commit `7c6e65c`; rerun hardware smoke after
  settings or reset UI/state changes.
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
`call_method` skeleton consumes the stored active default-reject policy decision
only for Sui `sign_transaction` policy-decision smoke; it does not sign, update
policy, expose MCP directly, or apply signing policy to produce signatures. It
does persist bounded approval-history metadata for those method decisions. The
persisted values in this target implementation are the protocol `deviceId`,
provisioning state flag, DEV_PROFILE root entropy blob after backup
confirmation, a DEV_PROFILE active default-reject policy record, and a
DEV_PROFILE local PIN verifier, the optional connect-PIN setting, and the
approval-history ring buffer.

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
tools/firmware/stackchan-cores3/test_call_method_validation.sh
tools/firmware/stackchan-cores3/test_method_runtime.sh
tools/firmware/stackchan-cores3/test_policy_store.sh
tools/firmware/stackchan-cores3/test_persistent_material.sh
tools/firmware/stackchan-cores3/test_provisioning_state_store.sh
tools/firmware/stackchan-cores3/test_local_auth.sh
tools/firmware/stackchan-cores3/test_local_auth_worker.sh
tools/firmware/stackchan-cores3/test_local_pin_auth.sh
tools/firmware/stackchan-cores3/test_connect_settings.sh
tools/firmware/stackchan-cores3/test_approval_history.sh
tools/firmware/stackchan-cores3/test_session.sh
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
`products/firmware/src/common/agent_q/policy` plus the Sui method adapter and
verifies deny-by-default, `sign`/`reject`/`ask` decision calculation, default
provider behavior, missing/invalid policy provider rejection, malformed policy
rejection, and unsupported-facts rejection. StackChan CoreS3 consumes the
stored active default-reject decision only for Sui `sign_transaction`
policy-decision smoke; policy is not connected to physical approval, capability
advertisement, policy update, or signing.

The StackChan policy-store test is target-specific. It compiles the tracked
`agent_q_policy_store.cpp` provider with ESP-IDF mbedTLS SHA-256 sources and
host NVS stubs, then verifies default-policy storage, policy id calculation,
summary reads, wipe behavior, active-policy availability checks, and
missing/corrupt/failed-write fail-closed provider behavior.

The StackChan approval-history test is target-specific. It compiles the tracked
`agent_q_approval_history.cpp` store with ESP-IDF mbedTLS SHA-256 sources and
host NVS stubs, then verifies persistent ring-buffer append, newest-first
pagination, payload digest formatting, wipe behavior, and corrupt-record
fail-closed behavior.

The StackChan method-runtime test is target-specific. It compiles the tracked
`agent_q_method_runtime.cpp` runtime boundary with ArduinoJson, the common Sui
facts parser, the common policy runtime, and pinned MicroSui base64 helpers,
then verifies unsupported method rejection, invalid Sui params, approval-history
metadata exposure, and the default-reject policy result for a valid restricted
SUI transfer fixture.

The StackChan persistent-material test is target-specific. It compiles the
tracked `agent_q_persistent_material.cpp` coordinator with host material stubs,
then verifies setup commit ordering and rollback, reset wipe coverage,
provisioning-state storage envelope classification, loaded-state consistency
classification, typed runtime material failure handling, persistent-material
consistency error latch ownership, and legacy missing-policy migration.

The StackChan provisioning-state store test is target-specific. It compiles the
tracked `agent_q_provisioning_state_store.cpp` NVS adapter with host NVS stubs,
then verifies missing/present/unreadable storage classification and state
writes. Persistent-material consistency meaning remains owned by
`agent_q_persistent_material.cpp`.

The StackChan local-auth test is target-specific. It compiles the tracked
`agent_q_local_auth.cpp` verifier store with the pinned MicroSui Monocypher
source plus host NVS/RNG stubs, then verifies exact 6-digit PIN validation,
PBKDF2-HMAC-SHA512 verifier storage, correct/wrong PIN checks, fresh salt,
wipe behavior, and corrupt/failed-write fail-closed behavior. This verifier is
a DEV_PROFILE local UX gate, not root-material encryption.

The StackChan local-auth worker test is target-specific. It compiles the
tracked `agent_q_local_auth_worker.cpp` task boundary with host FreeRTOS stubs,
then verifies worker request queue entries carry only job metadata and never raw
PIN bytes.

The StackChan local-reset test is target-specific. It compiles the tracked
`agent_q_local_reset.cpp` state machine with host NVS/material stubs, then
verifies normal reset and error-state erase recovery transitions, reset-pending
marker behavior, destructive wipe orchestration, and failure cleanup. This is a
host-side state-machine check, not hardware UX proof.

The StackChan provisioning-flow test is target-specific. It compiles the
tracked `agent_q_provisioning_flow.cpp` state machine with host stubs, then
verifies Generate/Recover/setup-PIN volatile state transitions, scratch
lifetime, panel-loss cleanup, and commit-readiness without LVGL or USB.

The StackChan session test is target-specific. It compiles the tracked
`agent_q_session.cpp` RAM session core with host stubs, then verifies session id
generation, validation result classification, mismatch handling, expiry, and
scheduled cleanup without USB JSON response code.

During preparation, the tracked build tools also patch the pinned upstream host
tree so the Agent-Q build does not start the StackChan/Xiaozhi remote AI
runtime, does not register Xiaozhi remote MCP tools, does not initialize the
camera, and does not start remote avatar WebSocket service.

## Current Integration Points

In the hardware firmware tree:

- Add `agent_q/*.cpp` to the main firmware component sources.
- Add `agent_q_common/sui/*.cpp` to the main firmware component sources for the
  shared hardware-independent Sui parser and method adapter.
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
- Call `agent_q::notify_agent_q_ui_surface_ready()` after the target attaches
  the default avatar to let Agent-Q draw the current idle UI for the active
  device state.

## Persistent Storage

This target stores the protocol `deviceId`, provisioning state, DEV_PROFILE root
entropy, active default-reject policy, local PIN verifier, optional connect-PIN
setting, and approval-history ring buffer in NVS namespace `agent_q`.
When a previous DEV_PROFILE build already has `prov_state = provisioned` and
valid root entropy but no policy record, boot initializes the default-reject
policy before reporting `provisioned`; if that write fails, the target fails
closed with a material/state consistency error. Devices missing the local PIN
verifier are not migrated and fail closed until reprovisioned.

| Key | Purpose |
|---|---|
| `device_id` | Gateway reconnect and device-selection identity |
| `prov_state` | Provisioning state flag; `provisioned` is valid only with root entropy, active policy, and local PIN verifier present |
| `root_entropy` | DEV_PROFILE BIP-39 root entropy blob; not exported over USB |
| `policy_v0` | DEV_PROFILE active default-reject policy record |
| `pin_auth` | DEV_PROFILE salt + PBKDF2-HMAC-SHA512 local PIN verifier; not root encryption |
| `pin_on_connect` | Optional local connect approval setting; missing means require PIN on connect; local reset erases it back to the missing-key default |
| `approval_hist` | Fixed-size 32-record binary approval-history ring buffer; local reset and error-state erase wipe it |

Device-local recovery phrase setup stores generated phrase text and recovered mnemonic
word-entry scratch only in RAM. Generate displays only up-to-4-letter prefixes
on device and advances to local 6-digit PIN setup on backup confirmation.
Recover uses device-local A-Z prefix buttons and scrollable BIP-39 candidate
bubbles, verifies checksum, and then advances to the same PIN setup path.
Volatile setup scratch is wiped on cancel, display expiry, PIN timeout, storage
failure, or firmware restart. Backup-confirmed or checksum-verified root entropy
is stored as DEV_PROFILE scaffolding only after the repeated PIN matches; this
build does not enable USER_PROFILE encrypted storage. Three-letter BIP-39 words
are displayed as the full word.

Agent-Q-owned modules are sources under `agent_q/` in this target tree. These
modules may share the `agent_q` namespace. New keys should be named by feature,
such as `<feature>_<name>`, to avoid collisions.
