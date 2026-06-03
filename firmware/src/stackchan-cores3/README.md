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
  `provisioned`, with no public methods.
- a USB JSONL `get_approval_history` request that returns bounded persistent
  Firmware-authored method-decision and policy-update terminal metadata over an
  approved session. It is read-only, rate-limits method-decision persistent
  writes to reduce flash wear, stores no raw requests or secrets, and records
  validated `call_method` policy-rejected decisions and recordable
  `propose_policy_update` terminal results.
- a USB JSONL `call_method` path. It requires material-backed `provisioned`
  state plus a matching active session, keeps unknown methods rejected with
  `unsupported_method`, and validates Sui `sign_transaction` restricted SUI
  transfer request inputs for rejected-path policy evaluation. Public signing
  output is not implemented.
- a source-level device-confirmed signature request state owner for future
  `request_signature` work. It owns RAM-only pending request metadata, bounded
  signable payload scratch, a Sui transfer summary parsed from the same
  `txBytes`, Firmware-derived sender/gas-owner account binding, staged
  confirmation, terminal cleanup, and one-shot payload handoff after the
  required confirmation history write succeeds. The history write receives
  value-owned request metadata and cannot move a cleared or different request
  into the signing critical section. A host-tested review view model turns a
  reviewing snapshot into bounded clear-signing rows that include the full
  recipient, amount, asset, network, gas budget, and gas price without using UI
  object lifetime as state. The approval-history store and parser can
  represent bounded future signature-request confirmation and terminal records,
  using the current approval-history storage layout only. The state owner is not
  connected to USB protocol ingress, LVGL review drawing, local PIN UI, signing service calls,
  Gateway/client/provider signing parsers, or capability
  advertisement.
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
  approval history, policy-update terminal marker, connect-approval setting,
  runtime session, and provisioning state, and is not exposed as a USB JSONL
  request. Hardware smoke coverage exists for local reset. Targeted hardware
  verification remains required after settings or reset UI/state changes.
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

This target reports read-only identity capability with no public methods,
derives read-only public account identity
(`get_accounts`), and links a restricted host-tested Sui transaction facts
parser plus a common stored-policy runtime boundary. The current `call_method`
path consumes the committed active policy decision for Sui `sign_transaction`,
rejects unsupported transactions, and returns rejected method results. It also
implements the Firmware-owned `propose_policy_update` admin method for bounded
reject-policy proposals over an active session, local PIN approval, canonical
active-policy commit, and required policy-update terminal history. It does not
expose MCP
directly; Gateway/MCP only submit requests and parse Firmware responses. It
does persist bounded approval-history metadata for method decisions and policy
update terminal records. The
persisted values in this target implementation are the protocol `deviceId`,
provisioning state flag, DEV_PROFILE root entropy blob after backup
confirmation, canonical active policy slots plus commit metadata and a
pending-write marker, a policy-update terminal marker, a DEV_PROFILE local PIN
verifier, the optional connect-PIN setting, and the approval-history ring
buffer. The normal provisioning flow still installs only the default-reject
policy; custom policies enter only through the session-scoped
`propose_policy_update` proposal path.

The active policy store treats commit metadata write as the commit point. The
write path classifies terminal state as applied, previous policy proven
unchanged, or consistency error. Firmware recognizes only the current tracked
active-policy storage layout as product state.

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
`firmware/source.env`. Tracked tools use those files so local builds
and GitHub Actions use the same inputs:

```bash
AGENT_Q_IDF_PATH=/path/to/esp-idf-v5.5.4 \
  firmware/tools/stackchan-cores3/with-idf.sh \
  firmware/tools/stackchan-cores3/build.sh
```

The `with-idf.sh` launcher activates ESP-IDF with Python 3.11 by default so the
same build directory is not reconfigured by different ESP-IDF Python virtual
environments. Set `AGENT_Q_IDF_PYTHON=/path/to/python` only if the local machine
does not expose `python3.11`.

Host checks that require ESP-IDF should use the same launcher around the
specific command:

```bash
AGENT_Q_IDF_PATH=/path/to/esp-idf-v5.5.4 \
  firmware/tools/stackchan-cores3/with-idf.sh \
  firmware/tools/stackchan-cores3/test_policy_store.sh
```

Other checks can be run directly when their script header says ESP-IDF is not
required:

```bash
firmware/tools/common/generate_sui_transaction_fixtures.mjs
firmware/tools/common/test_sui_transaction_facts.sh
firmware/tools/common/test_policy_v0.sh
firmware/tools/stackchan-cores3/test_call_method_validation.sh
firmware/tools/stackchan-cores3/test_method_runtime.sh
firmware/tools/stackchan-cores3/test_policy_proposal_parser.sh
firmware/tools/stackchan-cores3/test_policy_update_flow.sh
firmware/tools/stackchan-cores3/test_policy_update_marker.sh
firmware/tools/stackchan-cores3/test_prepare_sync.sh
firmware/tools/stackchan-cores3/test_persistent_material.sh
firmware/tools/stackchan-cores3/test_provisioning_state_store.sh
firmware/tools/stackchan-cores3/test_provisioning_runtime_state.sh
firmware/tools/stackchan-cores3/test_signature_request_flow.sh
firmware/tools/stackchan-cores3/test_signature_request_review_view_model.sh
firmware/tools/stackchan-cores3/test_local_auth.sh
firmware/tools/stackchan-cores3/test_local_auth_worker.sh
firmware/tools/stackchan-cores3/test_local_pin_auth.sh
firmware/tools/stackchan-cores3/test_connect_approval.sh
firmware/tools/stackchan-cores3/test_protocol_pin_approval.sh
firmware/tools/stackchan-cores3/test_identification_display.sh
firmware/tools/stackchan-cores3/test_local_settings_touch_entry.sh
firmware/tools/stackchan-cores3/test_usb_link_state.sh
firmware/tools/stackchan-cores3/test_usb_session_loss.sh
firmware/tools/stackchan-cores3/test_ui_panel_cleanup.sh
firmware/tools/stackchan-cores3/test_connect_settings.sh
firmware/tools/stackchan-cores3/test_session.sh
firmware/tools/stackchan-cores3/test_sui_signing_service.sh
firmware/tools/stackchan-cores3/test_sui_account_vectors.sh
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
`agent_q_sui_key_derivation.cpp` and `agent_q_sui_account.cpp` derivation
modules with the pinned MicroSui signing source and checks known Sui SDK
address/public-key vectors.

The Sui signing service test is host-side. It compiles the internal
`agent_q_sui_signing_service.cpp` substrate with the pinned MicroSui signing
source and verifies the deterministic Sui transaction signature vector,
signature verification, invalid-input output wiping, and the stored-root
signing boundary with host stubs. This is not a protocol signing test.

The Sui transaction facts parser test is a common host-side check. It compiles
`firmware/src/common/agent_q/sui` and verifies tracked BCS fixtures for
the restricted SUI transfer parser. StackChan CoreS3 connects the parser to Sui
`sign_transaction` rejected-path policy evaluation.

The policy test is also a common host-side check. It compiles
`firmware/src/common/agent_q/policy` plus the Sui method adapter and
verifies deny-by-default reject decisions, default provider behavior,
missing/invalid policy provider rejection, malformed policy rejection, and
unsupported-facts rejection. StackChan CoreS3 consumes the
committed active policy for restricted Sui `sign_transaction` policy evaluation
and rejected method results. Custom policy updates enter separately through the
Firmware-owned `propose_policy_update` proposal flow.

The StackChan policy-store test is target-specific. It compiles the tracked
`agent_q_policy_store.cpp` provider with ESP-IDF mbedTLS SHA-256 sources and
host NVS stubs, then verifies default-policy storage, policy id calculation,
summary reads, wipe behavior, active-policy availability checks, pending-marker
torn-write rollback, metadata-flip commit-point behavior, stale pending-marker
overlap handling, stale commit pre-erase failure handling, and
missing/corrupt/failed-write fail-closed provider behavior.

The StackChan approval-history test is target-specific. It compiles the tracked
`agent_q_approval_history.cpp` store with ESP-IDF mbedTLS SHA-256 sources and
host NVS stubs, then verifies persistent ring-buffer append, newest-first
pagination, payload digest formatting, unsupported-layout rejection, wipe
behavior, required policy-update terminal record shape, method-decision write
budgeting, and corrupt-record fail-closed behavior.

The StackChan policy-update marker test is target-specific. It compiles the
tracked `agent_q_policy_update_marker.cpp` NVS record boundary with host stubs,
then verifies the persistent terminal marker's pending/clear states, input
validation, corrupt-marker fail-closed behavior, and storage-error reporting.
This marker is a policy-update terminal substrate only; it is not a protocol
policy-update handler.

The StackChan method-runtime test is target-specific. It compiles the tracked
`agent_q_method_runtime.cpp` runtime boundary with ArduinoJson, the common Sui
facts parser, the common policy runtime, and pinned MicroSui base64 helpers,
then verifies unsupported method rejection, invalid Sui params, approval-history
metadata exposure, the default-reject policy result for a valid restricted SUI
transfer fixture, and rejected-path scratch cleanup.

The StackChan policy-proposal parser test is target-specific. It compiles the
tracked `agent_q_policy_proposal_parser.cpp` parser with ArduinoJson and the
common policy canonicalizer, then verifies bounded serialized proposal-object parsing,
reject-only action enforcement, method/field/operator validation, embedded-NUL
string rejection, canonical unsigned integer policy values, serialized
policy-object bounds, and current canonical record validation. The parser does not
implement raw protocol envelope handling, policy storage, pending update state,
or approval UI by itself.

The StackChan persistent-material test is target-specific. It compiles the
tracked `agent_q_persistent_material.cpp` coordinator with host material stubs,
then verifies setup commit ordering and rollback, reset wipe coverage,
provisioning-state storage envelope classification, loaded-state consistency
classification, typed runtime material failure handling, persistent-material
consistency error latch ownership, and policy-update marker wipe coverage.

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
generation, validation result classification, mismatch handling, and
link-bound lifetime without USB JSON response code.

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
- Patch the generated StackChan `partitions.csv` so the Agent-Q target owns a
  64 KiB NVS partition. The upstream 16 KiB NVS layout is too small for the
  current Agent-Q root material, two-slot active policy store, approval-history
  ring buffer, local PIN verifier, settings, and terminal markers.
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
entropy, committed active policy records, local PIN verifier, optional
connect-PIN setting, and approval-history ring buffer in NVS namespace
`agent_q`. The StackChan build preparation step patches the generated firmware
partition table to use a 64 KiB NVS partition; the upstream 16 KiB default is
not sufficient for the current Agent-Q material set.
If NVS has `prov_state = provisioned` and valid root entropy but no active
canonical policy record, Firmware fails closed with a material/state consistency
error. Unsupported current policy-history or policy-storage blobs are not
accepted as product state; destructive local reset or error-state erase is the
supported recovery path. Devices missing the current local PIN verifier fail
closed until reprovisioned.

| Key | Purpose |
|---|---|
| `device_id` | Gateway reconnect and device-selection identity |
| `prov_state` | Provisioning state flag; `provisioned` is valid only with root entropy, active policy, and local PIN verifier present |
| `root_entropy` | DEV_PROFILE BIP-39 root entropy blob; not exported over USB |
| `pol_s0`, `pol_s1` | Active policy canonical record slots |
| `pol_c0`, `pol_c1` | Active policy commit metadata records |
| `pol_p` | Active policy pending-write marker used to distinguish interrupted inactive-slot writes from post-commit corruption |
| `pol_um` | Policy-update terminal marker; presence means an incomplete policy-update terminal sequence is material inconsistency |
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
