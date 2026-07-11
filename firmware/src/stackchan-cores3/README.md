# StackChan CoreS3 Firmware Source

> Development status: Agent-Q is an active development project with
> hardware-tested Sui signing paths for CLI, MCP, and supported provider flows.
> The current StackChan CoreS3 Firmware path uses DEV_PROFILE material intended
> for development and demos, not real-asset custody. See the root README
> Current Status section for storage and profile limitations.

This directory contains the StackChan CoreS3 hardware-specific Agent-Q firmware
source overlay.

Target-specific behavior and capability status live in `SPEC.md`.

## Quick Start

Use this target when building Agent-Q Firmware for StackChan CoreS3 /
ESP32-S3-class hardware.

Build:

```bash
FIRMWARE_IDF_PATH=/path/to/esp-idf-v5.5.4 \
  firmware/tools/stackchan-cores3/with-idf.sh \
  firmware/tools/stackchan-cores3/build.sh
```

When no custom checkout path is passed, the build script generates the upstream
ESP-IDF project under `.firmware-cache/stackchan-cores3/StackChan/firmware` and
uses `build-stackchan-cores3` as the build directory. There is no
Agent-Q protocol command for flashing. To flash the default build, run ESP-IDF
against that generated project and the target serial port:

```bash
FIRMWARE_IDF_PATH=/path/to/esp-idf-v5.5.4 \
  firmware/tools/stackchan-cores3/with-idf.sh \
  idf.py \
    -C .firmware-cache/stackchan-cores3/StackChan/firmware \
    -B .firmware-cache/stackchan-cores3/StackChan/firmware/build-stackchan-cores3 \
    -p /dev/cu.usbmodemXXXX \
    flash
```

If you pass a custom host firmware checkout or build directory to `build.sh`,
use the matching generated firmware path and build directory for `idf.py`.

After flashing a current build, verify the product path through the normal
device UX:

```text
device-local setup or existing provisioned device
  -> connect approval
  -> get_capabilities
  -> get_accounts
  -> sign_transaction
  -> sign_personal_message when user-mode support is reported
  -> disconnect
```

Use development erase/reprovisioning only when explicitly approved for a
hardware smoke pass. Setup, reset, and signing approval are device-local flows;
they are not exposed as USB state-setter APIs.

For each hardware smoke pass, record the target hardware, repository commit,
build command, flash command, serial port, manual device-local steps, observed
result, and unchecked paths. Keep scratch evidence under `.WORK/notes/`, and
update tracked status documents only when the verification level changes.

## Current Implementation

The current implementation includes:

- a boot-time signing self-test that proves the firmware can link the signing
  dependency, create an Ed25519 Sui-formatted signature from a runtime-generated
  test seed, verify that signature on the device, and log the result without
  showing boot UI.
- a USB JSONL `get_status` request that follows the shared protocol envelope and
  returns a persistent device id plus the current device state without showing a
  physical approval UI. Before reporting status, the target refreshes
  persistent-material consistency and may fail closed by reporting `error` and
  clearing stale runtime session state.
- a USB JSONL `identify_device` request that shows a short temporary code over
  the current screen and then returns to the previous device state.
- protocol handling for `connect` and `disconnect`. The current target creates a
  new session only after material-backed `provisioned` state and device-local
  approval. The target shows a connect review modal first; the device-local
  human approval input mode then selects either stored-PIN entry or physical
  Confirm. A sessionless `connect` on the same USB physical link can recover an
  already approved live RAM session without new approval or replacement.
  Changing that input mode is a local Settings action and requires stored PIN
  verification. Firmware sessions are RAM-only and do not authorize signing.
- a USB JSONL `get_capabilities` request that returns Firmware-authored Sui
  account identity capability over an approved session while `provisioned`:
  native Ed25519 when no zkLogin proof is active, or the active zkLogin identity
  when proof material is active. It reports no delegated public methods and
  top-level `signing` availability. `signing.authorization` is read-only
  Firmware state for the current device-local signing mode. While native
  identity is active, `credentials[]` may advertise common Sui zkLogin
  `credential_prepare`/`credential_propose` availability.
- a USB JSONL `get_accounts` request that returns exactly one active Sui
  account identity over an approved session while `provisioned`: the native
  Sui Ed25519 account or the locally stored Sui zkLogin identity. It exposes no
  private material, raw JWT, OAuth token, or proof secret.
- a USB JSONL `get_approval_history` request that returns bounded persistent
  Firmware-authored signing and policy-update terminal metadata over an
  approved session. It is read-only, stores no raw requests or secrets, and
  records validated `sign_transaction` policy confirmation records only after
  policy approval, user confirmation records only after device-local approval,
  terminal signing records for signed/failed/rejected/timed-out outcomes as
  applicable, user-mode `sign_personal_message` confirmation/terminal metadata,
  and recordable `policy_propose` terminal results. Product-active status is
  tracked in `docs/IMPLEMENTATION_STATUS.md`.
- a USB JSONL `sign_transaction` path. It requires material-backed `provisioned`
  state plus a matching active session, keeps unknown methods rejected with
  `unsupported_method`, and accepts Sui transaction bytes either inline or
  through same-session staged payload delivery before Firmware parsing.
  Firmware reads the device-local signing authorization mode. Policy mode
  validates active policy availability, request network scope, account binding,
  and Firmware-derived offline policy condition facts, then signs only when the
  active current policy has a matching `sign` policy. User mode
  starts offline facts review when complete offline facts review coverage
  exists, or a blind-signing warning when Firmware can validate and bind the
  transaction but offline facts review coverage is incomplete. Both user paths
  require the current human approval input mode without applying active policy
  as an additional filter.
  It returns `signed` only after required history is durable and signing
  succeeds. Unsupported Sui transaction semantics, caller-selected
  authorization, caller-controlled timing fields, and chain-specific top-level
  signing APIs fail closed or are not implemented. Product-active status is
  tracked in `docs/IMPLEMENTATION_STATUS.md`.
- a common bounded `(type, chain, method)` signing route classifier before
  state/session work. Unsupported chains return `unsupported_chain`;
  unsupported or type-mismatched Sui methods return `unsupported_method`. The
  Sui transaction and personal-message adapters retain their decoded-payload
  capacities; common ingress does not treat those capacities as
  request-format limits.
- a USB JSONL `sign_personal_message` path. It requires material-backed
  `provisioned` state plus a matching active session, validates bounded Sui
  personal-message bytes, and is available only when the device-local signing
  authorization mode is `user`. User mode shows clear-signing review and
  requires the current human approval input mode before signing the Sui
  PersonalMessage intent digest. Policy mode fails closed with
  `unsupported_method`; policy facts and
  rules for personal-message signing are not implemented. Detailed hardware
  evidence and product-active status are tracked in `docs/IMPLEMENTATION_STATUS.md`.
- a device-local mnemonic setup flow. The local setup speech bubble opens a
  Generate/Import choice. Generate creates DEV_PROFILE BIP-39 root entropy in
  RAM, displays only the up-to-4-letter word prefixes on device in a 3-column
  by 4-row grid, and advances to local 6-digit PIN entry after the backup
  phrase panel's local `Confirm` button. Import accepts 12 BIP-39 words
  through a device-local 3-word-per-page prefix/candidate UI, verifies checksum,
  and then advances to the same local PIN setup path. The target stores the root
  entropy plus active default-reject policy plus salt/PIN verifier plus signing
  authorization mode only after the repeated PIN matches. Local Cancel controls
  wipe volatile setup scratch.
  These setup transitions are not exposed as USB JSONL requests.
- device-local settings flows for `provisioned` devices: human approval input
  mode toggle, signing authorization mode toggle, policy reset to the default
  reject policy, Change PIN, and Device reset, plus a chain
  account menu whose current Sui account view displays active identity/proof
  state and can clear the local zkLogin proof. Policy reset, signing-mode
  changes, zkLogin proof clear, Change PIN, and Device reset require local PIN
  verification. Proof clear wipes only Sui zkLogin proof material, ends the
  active session, and restores the Sui account view from current device state.
  Change PIN verifies the current stored 6-digit PIN, accepts and repeats a new
  PIN, and replaces only the salt/PIN verifier. Device reset is the single
  user-facing wallet initialization action in Settings: it erases root material
  and returns the device to
  `unprovisioned`. Root-preserving settings repair is an internal
  storage-maintenance path for material/state consistency errors, not a normal
  Settings menu action and not a USB JSONL request. Current-tree hardware smoke
  has confirmed root-preserving settings repair after current-schema
  mutable-settings corruption and explicit Device reset returning the device to
  `unprovisioned`. Targeted hardware verification remains required after
  storage-maintenance UI/state changes.
- a locked-down Agent-Q firmware profile that keeps only the local launcher,
  local default avatar idle surface, and USB Agent-Q request server. It does not
  start the StackChan/Xiaozhi remote AI runtime, does not register Xiaozhi MCP
  tools, does not initialize the camera, does not start the setup/login worker,
  ignores Xiaozhi vision capabilities, and disables the remote WebSocket avatar
  service.
- an Agent-Q-only avatar UI layer. The StackChan default avatar face stays
  visible, the upstream default speech bubble is hidden by default, and Agent-Q
  requests use Agent-Q-owned speech-bubble decorators, modal review panels for
  external-request human approval, local PIN panels where required, and
  state-specific colors.
- target-local display-power handling that turns the screen backlight off after
  three minutes of inactivity, wakes for Agent-Q request UI, toggles display power
  on side-button short press, and powers off on side-button long press. Before
  screen-off or power-off, the target moves to a rest posture; when the screen
  wakes, it returns to awake posture.
- StackChan-specific boot and sleep posture feedback that centers yaw and
  raises pitch after the default avatar is attached or the screen wakes, then
  moves to centered yaw and lowered pitch before screen-off or power-off.

Runtime Firmware sessions are implemented only as RAM-held protocol sessions.
The current target creates a new session after material-backed provisioning and
can recover an approved live session on the same USB physical link. Sessions do
not authorize signing.

This target reports read-only identity capability with no delegated public
methods plus top-level `signing`, derives read-only public account identity
(`get_accounts`), and links a host-tested Sui `TransactionData` facts extractor
plus current policy document storage/readback and offline condition-facts
extraction. The current
`sign_transaction` path reads the Firmware-local signing authorization mode and
uses exactly one gate: policy mode validates active policy availability,
request network scope, account binding, and complete offline policy condition
facts, then signs only when the active current policy has a matching `sign`
policy, while
user mode may enter offline facts review or blind-signing device confirmation
after Firmware validates and account-binds the transaction.
For Sui transactions, the parsed sender must match the active account. The
parsed gas owner must also match unless the active Sui account setting accepts
gas sponsors; accepted sponsored transactions still return only the active
sender signature.
User mode then applies the current human approval input mode and records
required history. Policy-incomplete valid transactions return `policy_rejected`
in policy mode. It rejects unsupported transactions and returns `signed`,
`policy_rejected`, `user_rejected`, `user_timed_out`, or `signing_failed`
through signing outcomes as applicable. Product-active status is tracked in
`docs/IMPLEMENTATION_STATUS.md`; do not infer it from source paths alone.
The target also exposes user-mode `sign_personal_message` for bounded Sui
personal-message bytes; policy mode fails closed for that method until matching
policy facts and rules are implemented. Product-active status is tracked in
`docs/IMPLEMENTATION_STATUS.md`.

This target also implements the Firmware-owned `policy_propose` request
for bounded current-schema policy proposals over an active session, a
device-local policy summary review, local PIN approval after device-local
Continue, canonical active-policy commit, and required policy-update terminal
history. It does not expose MCP directly; the host process and MCP only submit requests and
parse Firmware responses. It does persist bounded approval-history metadata for
signing and policy update terminal records. The
persisted values in this target implementation are the protocol `deviceId`,
provisioning state flag, DEV_PROFILE root entropy blob after backup
confirmation, canonical active policy slots plus commit metadata and a
pending-write marker, a policy-update terminal marker, a DEV_PROFILE local PIN
verifier, the human approval input mode setting, and the approval-history ring
buffer. The normal provisioning flow still installs the default-reject policy;
the session-scoped `policy_propose` proposal path accepts bounded
current-schema policy material.

The active policy store treats commit metadata write as the commit point. The
write path classifies terminal state as applied, previous policy proven
unchanged, or consistency error. Firmware recognizes only the current tracked
active-policy storage layout as product state.

Agent-Q firmware is not a general StackChan AI firmware. It does not include
StackChan World login, Xiaozhi cloud sessions, camera upload, screen snapshot
upload, remote video, app center, setup, EzData, or other non-Agent-Q remote
surfaces. Upstream StackChan firmware is not an Agent-Q signing device.

## Source And Build

This directory is an Agent-Q overlay for the upstream StackChan firmware host
tree. It is not a complete standalone ESP-IDF project.

The pinned upstream host source and ESP-IDF version live in this directory's
`source.env`. Shared firmware dependency pins live in
`firmware/source.env`. Tracked tools use those files so local builds
and GitHub Actions use the same inputs:

```bash
FIRMWARE_IDF_PATH=/path/to/esp-idf-v5.5.4 \
  firmware/tools/stackchan-cores3/with-idf.sh \
  firmware/tools/stackchan-cores3/build.sh
```

The `with-idf.sh` launcher activates ESP-IDF with Python 3.11 by default so the
same build directory is not reconfigured by different ESP-IDF Python virtual
environments. Set `FIRMWARE_IDF_PYTHON=/path/to/python` only if the local machine
does not expose `python3.11`.

Host checks that require ESP-IDF should use the same launcher around the
specific command:

```bash
FIRMWARE_IDF_PATH=/path/to/esp-idf-v5.5.4 \
  firmware/tools/stackchan-cores3/with-idf.sh \
  firmware/tools/stackchan-cores3/test_policy_store.sh
FIRMWARE_IDF_PATH=/path/to/esp-idf-v5.5.4 \
  firmware/tools/stackchan-cores3/with-idf.sh \
  firmware/tools/stackchan-cores3/test_signing_preflight_order.sh
FIRMWARE_IDF_PATH=/path/to/esp-idf-v5.5.4 \
  firmware/tools/stackchan-cores3/with-idf.sh \
  firmware/tools/stackchan-cores3/test_sign_request_identity_vectors.sh
```

Other checks can be run directly when their script header says ESP-IDF is not
required:

```bash
firmware/tools/common/generate_sui_transaction_fixtures.mjs
firmware/tools/common/test_sui_transaction_facts.sh
firmware/tools/common/test_sui_offline_policy_facts.sh
firmware/tools/common/test_sui_sign_transaction_adapter.sh
firmware/tools/common/test_sign_route.sh
firmware/tools/common/test_policy_document.sh
firmware/tools/stackchan-cores3/test_signing_retry_response.sh
firmware/tools/stackchan-cores3/test_sui_signing_preparation.sh
firmware/tools/stackchan-cores3/test_sign_transaction_policy_runtime.sh
firmware/tools/stackchan-cores3/test_policy_proposal_parser.sh
firmware/tools/stackchan-cores3/test_policy_update_flow.sh
firmware/tools/stackchan-cores3/test_policy_update_marker.sh
firmware/tools/stackchan-cores3/test_prepare_sync.sh
firmware/tools/stackchan-cores3/test_persistent_material.sh
firmware/tools/stackchan-cores3/test_provisioning_state_store.sh
firmware/tools/stackchan-cores3/test_provisioning_runtime_state.sh
firmware/tools/stackchan-cores3/test_user_signing_confirmation.sh
firmware/tools/stackchan-cores3/test_user_signing_flow.sh
firmware/tools/stackchan-cores3/test_sign_transaction_user_ingress.sh
firmware/tools/stackchan-cores3/test_sign_personal_message_user_ingress.sh
firmware/tools/stackchan-cores3/test_sign_api_activation_boundary.sh
firmware/tools/stackchan-cores3/test_user_signing_review_view_model.sh
firmware/tools/stackchan-cores3/test_user_signing_critical_section.sh
firmware/tools/stackchan-cores3/test_sign_transaction_user_validation.sh
firmware/tools/stackchan-cores3/test_sign_personal_message_user_validation.sh
firmware/tools/stackchan-cores3/test_local_auth.sh
firmware/tools/stackchan-cores3/test_local_auth_worker.sh
firmware/tools/stackchan-cores3/test_local_pin_auth.sh
firmware/tools/stackchan-cores3/test_connect_approval.sh
firmware/tools/stackchan-cores3/test_protocol_pin_approval.sh
firmware/tools/stackchan-cores3/test_identification_display.sh
firmware/tools/stackchan-cores3/test_local_settings_touch_entry.sh
firmware/tools/stackchan-cores3/test_usb_link_state.sh
firmware/tools/common/test_protocol_transport_loss.sh
firmware/tools/stackchan-cores3/test_device_activity_projection.sh
firmware/tools/stackchan-cores3/test_ui_panel_cleanup.sh
firmware/tools/stackchan-cores3/test_modal_layout_static.sh
firmware/tools/stackchan-cores3/test_human_approval_settings.sh
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
`bip39.cpp` encoder with ESP-IDF mbedTLS SHA-256 sources and a
generated wordlist source from the pinned BIP-39 English wordlist.

The Sui account vector test is also host-side. It compiles the tracked
`sui_key_derivation.cpp` and `sui_account.cpp` derivation
modules with the pinned MicroSui signing source and checks known Sui SDK
address/public-key vectors.

The Sui signing service test is host-side. It compiles the internal
`sui_signing_service.cpp` substrate with the pinned MicroSui signing
source and verifies the deterministic Sui transaction signature vector,
signature verification, invalid-input output wiping, and the stored-root
signing boundary with host stubs. This is not a protocol signing test.

The Sui transaction facts parser test is a common host-side check. It compiles
`firmware/src/common/sui` and verifies tracked BCS fixtures for the Sui
`TransactionData` facts extractor, command argument refs, top-level TypeTag
facts, MoveCall package/module/function/type-argument facts, malformed ref
rejection, unsupported decoded shape classification, and generic PTB command
facts. StackChan CoreS3
connects the extractor to Sui `sign_transaction` policy and user authorization
gates for inline and staged transaction bytes.

The policy document tests are common host-side checks. They compile
`firmware/src/common/policy` and verify the current `signing.policy`
document shape, field/operator validation, canonical storage payloads, and
readback projection. The Sui offline policy facts test verifies the transaction
facts that the current policy evaluator consumes. StackChan CoreS3 connects
committed active policy material to Sui `sign_transaction` policy-mode signing
through the Firmware-owned runtime gate. Custom policy updates enter separately
through the Firmware-owned `policy_propose` proposal flow.

The StackChan policy-store test is target-specific. It compiles the tracked
`policy_store.cpp` provider with ESP-IDF mbedTLS SHA-256 sources and
host NVS stubs, then verifies default-policy storage, policy id calculation,
summary reads, wipe behavior, active-policy availability checks, pending-marker
torn-write rollback, metadata-flip commit-point behavior, stale pending-marker
overlap handling, stale commit pre-erase failure handling, and
missing/corrupt/failed-write fail-closed provider behavior.

The StackChan approval-history test is target-specific. It compiles the tracked
`approval_history.cpp` store with ESP-IDF mbedTLS SHA-256 sources and
host NVS stubs, then verifies persistent ring-buffer append, newest-first
pagination, payload digest formatting, unsupported-layout rejection, wipe
behavior, required policy-update terminal record shape, signing record shape,
and corrupt-record fail-closed behavior.

The StackChan policy-update marker test is target-specific. It compiles the
tracked `policy_update_marker.cpp` NVS record boundary with host stubs,
then verifies the persistent terminal marker's pending/clear states, input
validation, corrupt-marker fail-closed behavior, and storage-error reporting.
This marker is a policy-update terminal substrate only; it is not a protocol
policy-update handler.

The StackChan device-activity projection test is target-specific and host-side.
It compiles `device_activity_projection.cpp` and verifies active-flow
state projection and operation-specific gates, including policy-update review
and commit stages, local Settings entry blocking, signing ingress blocking, and
the idle Settings menu USB exception. It also verifies the retained-response
read/cleanup route class for `get_result` and `ack_result`. It is not a
hardware smoke test.

The StackChan sign_transaction policy runtime test is target-specific. It compiles the tracked
common `firmware/src/common/signing/sign_transaction_policy_runtime.cpp` runtime
boundary with ArduinoJson, the common Sui facts parser, current policy document support, and pinned MicroSui base64 helpers,
then verifies unsupported method rejection, invalid Sui params, approval-history
metadata exposure, current fail-closed policy behavior, and scratch cleanup.

The StackChan policy-proposal parser test is target-specific. It compiles the
tracked `policy_proposal_parser.cpp` parser with ArduinoJson and the
common policy canonicalizer, then verifies bounded serialized proposal-object parsing,
current-schema action enforcement, method/field/operator validation, embedded-NUL
string rejection, canonical unsigned integer policy values, serialized
policy-object bounds, and current canonical record validation. The parser does not
implement raw protocol envelope handling, policy storage, pending update state,
or approval UI by itself.

The StackChan persistent-material test is target-specific. It compiles the
tracked `persistent_material.cpp` coordinator with host material stubs,
then verifies setup commit ordering and rollback, storage-action coverage,
provisioning-state storage envelope classification, loaded-state consistency
classification, typed runtime material failure handling, persistent-material
consistency error latch ownership, and policy-update marker wipe coverage.

The StackChan provisioning-state store test is target-specific. It compiles the
tracked `provisioning_state_store.cpp` NVS adapter with host NVS stubs,
then verifies missing/present/unreadable storage classification and state
writes. Persistent-material consistency meaning remains owned by
`persistent_material.cpp`.

The StackChan local-auth test is target-specific. It compiles the tracked
`local_auth.cpp` verifier store with the pinned MicroSui Monocypher
source plus host NVS/RNG stubs, then verifies exact 6-digit PIN validation,
PBKDF2-HMAC-SHA512 verifier storage, correct/wrong PIN checks, fresh salt,
wipe behavior, and corrupt/failed-write fail-closed behavior. This verifier is
a DEV_PROFILE local UX gate, not root-material encryption.

The StackChan local-auth worker test is target-specific. It compiles the
tracked `local_auth_worker.cpp` task boundary with host FreeRTOS stubs,
then verifies worker request queue entries carry only job metadata and never raw
PIN bytes.

The StackChan storage-maintenance test is target-specific. It compiles the
tracked `storage_maintenance.cpp` state machine with host NVS/material stubs,
then verifies internal settings repair, Device reset, storage-action pending marker
behavior, root-preserving settings repair, destructive Device reset
orchestration, and failure cleanup. This is a host-side state-machine check,
not hardware UX proof.

The StackChan provisioning-flow test is target-specific. It compiles the
tracked `provisioning_flow.cpp` state machine with host stubs, then
verifies Generate/Import/setup-PIN volatile state transitions, scratch
lifetime, panel-loss cleanup, and commit-readiness without LVGL or USB.

The StackChan session test is target-specific. It compiles the tracked
`session.cpp` RAM session core with host stubs, then verifies session id
generation, validation result classification, mismatch handling, and
link-bound lifetime without USB JSON response code.

During preparation, the tracked build tools also patch the pinned upstream host
tree so the Agent-Q build does not start the StackChan/Xiaozhi remote AI
runtime, does not register Xiaozhi remote MCP tools, does not initialize the
camera, and does not start remote avatar WebSocket service.

## Current Integration Points

In the hardware firmware tree:

- Add `runtime/*.cpp` to the main firmware component sources.
- Add `firmware_common/sui/*.cpp` to the main firmware component sources for the
  shared hardware-independent Sui parser and offline policy facts extractor.
- Add `firmware_common/policy/*.cpp` to the main firmware component sources for
  the shared hardware-independent current policy document support.
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
- Call `signing::init_secure_random_from_early_boot_entropy()` before HAL
  initialization so backup phrase generation never depends on late direct
  `esp_fill_random()` while RF/ADC entropy is unavailable.
- Call `signing::run_signing_self_test()` once during boot after hardware
  initialization.
- Initialize NVS during the host firmware boot sequence before Agent-Q
  initialization.
- Call `signing::init_protocol_request_server()` once after boot checks and NVS
  initialization.
- `signing::init_protocol_request_server()` starts the protocol request task.
  The task keeps USB and implemented local-transport handling available even
  when another firmware mode takes over the main app loop.
- The request task gives a connected USB data link priority over local
  transport. USB host SOF blocks a new QR/BLE pairing window and closes an
  existing BLE carrier through the shared transport-loss process. USB removal
  does not restart BLE; the user must open a fresh QR from local Settings.
- Call `signing::notify_signing_ui_surface_ready()` after the target attaches
  the default avatar to let Agent-Q draw the current idle UI for the active
  device state.

## Persistent Storage

Local-transport identity storage uses the shared parameterized NVS mechanism.
This target owns its namespace and key names, random source, reset composition,
memory placement, UI, and target-specific storage-failure projection.

This target stores root signing material and the local PIN verifier separately
from mutable settings. The current `signing` NVS namespace holds protected
authority material: DEV_PROFILE root entropy and the local PIN verifier. The
protocol `deviceId` lives in the `device_identity` namespace because it is
stable device identity, not signing key material, authority-gate material, or
recoverable mutable settings. The `signing_state` NVS namespace holds mutable settings:
provisioning state, committed active policy records, human approval input mode,
signing authorization mode, Sui account settings, one optional bounded Sui
zkLogin proof record, approval-history ring buffer, and storage-maintenance
marker. Internal settings repair rebuilds `signing_state` and never deletes the
root entropy or local PIN verifier. The protected root-material and local-PIN
storage names under `signing` are the current permanent keystore contract, not
a mutable settings schema or compatibility path. Firmware updates must not
rename or move those records as part of settings repair. The StackChan build preparation step patches the generated firmware
partition table to use a 64 KiB NVS partition; the upstream 16 KiB default is
not sufficient for the current Agent-Q material set.
If current storage has `prov_state = provisioned` and valid root entropy but no active
canonical policy record, local PIN verifier, or signing authorization mode,
Firmware fails closed with a material/state consistency error. Unsupported
current policy-history or policy-storage blobs are not accepted as product
state; settings repair, Device reset, or development flash erase is the
supported recovery path according to the remaining authority-gate material.
Devices missing the current local PIN verifier or signing authorization mode
fail closed until Device reset or development flash erase.

| Namespace | Key | Purpose |
|---|---|---|
| `device_identity` | `device_id` | host process reconnect and device-selection identity; not wallet material |
| `signing` | `root_entropy` | DEV_PROFILE BIP-39 root entropy blob; not exported over USB; erased only by explicit destructive Device reset or development flash erase |
| `signing` | `pin_auth` | DEV_PROFILE salt + PBKDF2-HMAC-SHA512 local PIN verifier; protected authority-gate material, not root encryption |
| `signing_state` | `prov_state` | Provisioning state flag; `provisioned` is valid only with root entropy, active policy, local PIN verifier, and signing authorization mode present |
| `signing_state` | `pol_s0`, `pol_s1` | Active policy canonical record slots |
| `signing_state` | `pol_c0`, `pol_c1` | Active policy commit metadata records |
| `signing_state` | `pol_p` | Active policy pending-write marker used to distinguish interrupted inactive-slot writes from post-commit corruption |
| `signing_state` | `pol_um` | Policy-update terminal marker; presence means an incomplete policy-update terminal sequence is material inconsistency |
| `signing_state` | `sign_auth_mode` | Device-local signing authorization mode; setup initializes it to user and Settings can change it after local PIN verification |
| `signing_state` | `human_approval` | Human approval input mode setting; setup initializes it to `pin`, missing or invalid read fails closed to `pin`, internal settings repair restores the default, and Device reset removes it |
| `signing_state` | `sui_acct_set` | Sui account setting flags, including whether the active account accepts gas sponsors |
| `signing_state` | `sui_zkl_proof` | Bounded Sui zkLogin proof record used only for active account projection and final zkLogin signature-envelope construction; local proof clear, internal settings repair, Device reset, and error-state Device reset wipe it |
| `signing_state` | `approval_hist` | Fixed-size 8-record binary approval-history ring buffer; internal settings repair, Device reset, and error-state Device reset wipe it |
| `signing_state` | `storage_action` | Internal Firmware-owned marker used to resume an interrupted settings repair or Device reset commit at boot; not a protocol state or host API |

Device-local backup phrase setup stores generated phrase text and imported mnemonic
word-entry scratch only in RAM. Generate displays only up-to-4-letter prefixes
on device and advances to local 6-digit PIN setup on backup confirmation.
Import uses device-local A-Z prefix buttons and scrollable BIP-39 candidate
bubbles, verifies checksum, and then advances to the same PIN setup path.
Volatile setup scratch is wiped on cancel, display expiry, PIN timeout, storage
failure, or firmware restart. Backup-confirmed or checksum-verified root entropy
is stored as DEV_PROFILE scaffolding only after the repeated PIN matches; this
build does not enable USER_PROFILE encrypted storage. Three-letter BIP-39 words
are displayed as the full word.

Agent-Q-owned modules are sources under `runtime/` in this target tree. Storage
keys must stay in the namespace that matches their authority: protected root and
local-authentication material under `signing`, stable device identity under
`device_identity`, and mutable settings and proof state under `signing_state`.
Protected root and local-authentication key names are fixed keystore records.
New mutable settings keys should be named by feature, such as
`<feature>_<name>`, to avoid collisions.
