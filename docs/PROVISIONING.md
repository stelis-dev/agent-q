# Agent-Q Provisioning Flow

This document defines Agent-Q device provisioning for signing material.

This document separates target design from implemented setup behavior. Current
implementation status lives in `docs/IMPLEMENTATION_STATUS.md`.

## Purpose

Provisioning creates or imports the root signing material for a device. Firmware
then derives chain accounts from that material.

Provisioning is not a normal MCP signing path. Agent-facing MCP tools must not
create, import, export, display, or reset signing material.

## Security Rules

- Firmware owns signing material.
- The host process must not store mnemonics, seeds, private keys, or imported signing
  material.
- MCP clients must not receive mnemonics, seeds, private keys, or imported
  signing material.
- Firmware must not expose an export API after provisioning.
- Chain accounts expose only public keys and addresses.
- USER_PROFILE signing material is generated or imported only after firmware
  integrity protections are active.

USER_PROFILE firmware integrity requirements are defined in
`docs/SECURITY_MODEL.md`.

## Entry Points

Provisioning can start only from:

1. An unprovisioned device.
2. A destructive device-local reprovisioning/reset flow.

Reprovisioning is destructive. It wipes signing material, accounts, policy, and
replay state before creating or importing new signing material.

## Setup Paths

### Create New Mnemonic

Preferred path:

```text
device RNG
  -> generate mnemonic / root seed inside Firmware
  -> show mnemonic to user once
  -> user backs it up
  -> user confirms backup
  -> user enters and repeats a 6-digit local PIN on device
  -> Firmware stores root material locally
  -> Firmware stores an active default-reject policy locally
  -> Firmware stores a salt + PIN verifier locally
  -> Firmware exposes only public keys / addresses
```

Rules:

- The host never receives the root mnemonic or seed.
- The mnemonic is shown only during provisioning.
- After confirmation, the mnemonic is not shown again.
- If setup is canceled, Firmware wipes the generated material.
- A device is not `provisioned` unless root material, an active policy, a local
  PIN verifier, and a signing authorization mode are all present.
- The local PIN verifier is a DEV_PROFILE UX gate for connect approval when
  enabled, settings changes, local reset, the current policy-update proposal
  flow, and sensitive local writes. It is not root-material encryption or
  physical extraction defense.

### Import Existing Mnemonic

Device-local import path:

```text
user provides mnemonic
  -> Firmware validates it
  -> user enters and repeats a 6-digit local PIN on device
  -> Firmware stores root material locally
  -> Firmware stores an active policy locally
  -> Firmware stores a salt + PIN verifier locally
  -> Firmware exposes only public keys / addresses
```

Direct device input is preferred when hardware supports it. The current
StackChan CoreS3 DEV_PROFILE source implements device-local Import.
Host-assisted input is not implemented and would be weaker because the host
sees the root secret.

## Hardware Capability

Provisioning UX depends on hardware:

- Display + touch/keyboard: can support local generation, backup confirmation,
  and possibly local import.
- Display only: can show a generated mnemonic; import may need host assistance.
- Button-only or LED-only: cannot safely show or enter mnemonics; setup needs a
  weaker assisted flow or external secure setup tooling.

StackChan CoreS3 has display and touch hardware. Source-level DEV_PROFILE
backup phrase generation, backup confirmation, persistent root storage, and
read-only `get_accounts` Sui account derivation are implemented. The current
setup source also records a DEV_PROFILE local PIN verifier before reporting
`provisioned`, and initializes device-local signing authorization mode to
`user`. Source/build tests cover the provisioned host process and MCP session path
through `get_accounts`, policy-decision rejection, inline and same-session
staged Sui `sign_transaction` request validation for bounded
`TransactionData::V1 -> ProgrammableTransaction` bytes, the current
`sign_transaction` policy/user gate split, and the user-mode
`sign_personal_message` source path.
Hardware smoke coverage exists for StackChan CoreS3 local setup and PIN entry.
Targeted hardware verification remains required after setup UI or state changes.
Source-level local settings
reset/material wipe now exists for provisioned StackChan CoreS3 devices, with
hardware smoke coverage for local reset.
Device-local Import is implemented for DEV_PROFILE. USB, host process, and MCP mnemonic
import, host-assisted import, and arbitrary transaction signing are not
implemented. Automatic signing outside the bounded policy-authorized
`sign_transaction` path is not implemented.

## Chain Accounts

The root mnemonic or seed is chain-neutral. Chain adapters own their derivation
path, signing scheme, address calculation, and public key format.

Current executable chain:

- Sui

Rules:

- The host process must not derive private keys.
- Firmware returns public key/address data through `get_accounts`.
- The current Sign API source paths have `source-wired-not-product-active`
  status for Sui `sign_transaction` with inline or same-session staged
  transaction bytes decoded by the Firmware Sui `TransactionData::V1 ->
  ProgrammableTransaction` facts extractor, and for user-mode Sui
  `sign_personal_message`.
  Firmware reads its local signing authorization mode and selects one gate:
  policy mode signs only current-contract GasCoin-derived proven-SUI split-result transfer transactions
  with a matching bounded `sign` rule; other valid policy-incomplete Sui
  transactions return a policy rejection. User mode uses
  device-local offline facts review when complete offline facts review coverage
  exists, or an explicit blind-signing warning when Firmware can validate and
  bind the transaction but offline facts review coverage is incomplete.
  Requests cannot choose this mode or the human approval input mode.
  Personal-message signing is user-mode only and fails closed in policy mode.
  Product-active status is not claimed unless `docs/IMPLEMENTATION_STATUS.md`
  says the matching source, docs, tests, build, hardware, and visual evidence
  are complete.
- Agent-Q must not add chain-specific top-level MCP tools.

The current executable chain target is Sui Ed25519.

## Firmware State

Target provisioning states:

- `unprovisioned`: no root signing material is stored.
- `provisioning`: setup flow is active.
- `provisioned`: root signing material, an active policy, a local PIN verifier,
  and signing authorization mode exist.
- `error`: Firmware detected persistent-material inconsistency and is failing
  closed.
- `locked`: sensitive actions require local unlock.

The current DEV_PROFILE runtime implements the StackChan CoreS3 mnemonic UI flow and
persistent root material storage path. It loads and reports `provisioning.state`, but
does not persist `provisioning` during the normal create-new-mnemonic flow.
After physical backup confirmation, Firmware stores the binary BIP-39 root
entropy, the active default-reject policy, a salt + PIN verifier, and signing
authorization mode in ordinary DEV_PROFILE device-local NVS and only then moves
to `provisioned`.
Existing DEV_PROFILE devices with `prov_state = provisioned` but missing,
unreadable, or unsupported current active policy material fail closed.
Destructive local reset or error-state erase is the supported recovery path;
Firmware recognizes only the current tracked policy storage layout as product
state.
If the persisted state and required material records disagree after boot or
during runtime checks, Firmware reports `provisioning.state = error`; it does
not keep reporting `provisioned` while rejecting all session APIs.

The current DEV_PROFILE runtime does not import or export root signing material.
Read-only public Sui account derivation is available via `get_accounts`.
The current Sign API source paths exist for Sui `sign_transaction` transaction
bytes delivered inline or through same-session staging and for user-mode
`sign_personal_message` personal-message bytes. Sui transaction bytes are
decoded by the Firmware Sui `TransactionData::V1 -> ProgrammableTransaction`
facts extractor. Unsupported versions, unsupported transaction kinds,
malformed bytes, out-of-range command references, and transactions whose
minimum sender/gas-owner facts cannot be extracted and bound fail closed.
Valid account-bound transactions whose offline review facts are incomplete may
enter the explicit user-mode blind-signing path; policy mode rejects
policy-incomplete transactions and signs only current-contract GasCoin-derived
proven-SUI split-result transfer transactions with a matching bounded `sign`
rule. Product-active claims still depend on the
target evidence tracked in `docs/IMPLEMENTATION_STATUS.md`.
Current StackChan CoreS3 source can generate a BIP-39 backup
phrase as RAM scratch, display its up-to-4-letter word prefixes on device in a
3-column by 4-row grid, and wipe scratch on confirm, cancel, timeout, failure,
or display expiry. Three-letter BIP-39 words are displayed as the full word.
This is DEV_PROFILE storage scaffolding and is not USER_PROFILE key
provisioning. Firmware must not set `provisioned` unless root signing material,
an active policy, a local PIN verifier, and signing authorization mode exist in
device-local storage.
Firmware must not set `locked` until an unlock model exists.

Current DEV_PROFILE state transitions:

```mermaid
stateDiagram-v2
    [*] --> Unprovisioned: boot default or stored state
    Unprovisioned --> Unprovisioned: local setup opens phrase display
    Unprovisioned --> Unprovisioned: local Confirm, PIN entry active
    Unprovisioned --> Provisioned: matching PIN repeat, root material + policy + PIN verifier + signing mode stored
    Unprovisioned --> Unprovisioned: local Cancel/timeout/failure, scratch wiped

    Unprovisioned: no root signing material, active policy, local PIN verifier, or signing mode
    Unprovisioned: optional volatile mnemonic/root/PIN setup scratch only
    Provisioned: root material, active policy, local PIN verifier, and signing mode stored; read-only get_accounts/policy_get available; Sign API requests can run after session approval
```

The current runtime does not expose USB requests for provisioning start,
provisioning cancel, backup phrase confirmation, mnemonic import,
factory reset, or diagnostic display signaling. These transitions are
device-local UX only.

## Device-Local Backup And Import Setup

Current StackChan CoreS3 source enters setup only through the local setup speech
bubble shown while the device is `unprovisioned`. The first local setup panel
offers `Generate` and `Import`. The host process and MCP cannot start, cancel, confirm, or
import this setup flow through USB protocol messages.

Local setup generates 128-bit BIP-39 root entropy from an Agent-Q CSPRNG seeded
from early boot entropy before HAL initialization, then uses BIP-39 checksum
logic to render a 12-word backup phrase. Firmware keeps the root entropy and
phrase only in RAM until backup confirmation and displays only the
up-to-4-letter word prefixes on the device. Three-letter BIP-39 words are
displayed as the full word. The prefixes are shown as 12 numbered cells in 3
columns by 4 rows so they fit on one StackChan CoreS3 screen. BIP-39 English
word prefixes identify the words and are secret material; the host process never
receives them. No protocol response carries the phrase, prefixes, entropy,
seed, private key, account data, or policy data.

Firmware tracks the volatile setup flow with explicit RAM scratch substates:
`none`, `setup_choice`, `backup_phrase_displayed`, `import_word_entry`,
`pin_first_entry`, `pin_repeat_entry`, and `pin_committing`. This substate is
separate from the persistent
`provisioning.state`, session state, display power state, and LVGL panel state.
The UI is not the source of truth; panel deletion or replacement is treated as
an event that must wipe or invalidate the current setup scratch.

In the local import path, the device shows three word-entry cells per page for
four pages. The cells use the same numbered, bordered visual style as the
generated mnemonic prefix grid. The user selects a word cell, enters a
lowercase BIP-39 prefix through device-local A-Z buttons, then selects a
matching BIP-39 word from the scrollable on-device candidate bubbles. Import
word input is secret scratch owned by Firmware. `Next` is available only after
all three words on the page are selected. After all 12 words are selected,
Firmware reconstructs the 128-bit BIP-39 entropy and verifies the checksum.
Checksum failure stores nothing and keeps the user in local import entry;
Cancel, timeout, panel deletion, or display allocation failure wipes import
word scratch and leaves persistent state `unprovisioned`.

Backup confirmation is accepted only after a generated phrase has been
displayed. The device-local Confirm button does not store material by itself.
It advances the RAM scratch state to local PIN setup, wipes phrase text/prefix
scratch, and requires the user to enter and repeat a 6-digit numeric PIN on the
device. The import path reaches the same PIN setup state only after 12
selected BIP-39 words pass checksum validation. If the two PIN entries mismatch,
Firmware wipes only typed PIN scratch and returns to the first PIN entry while
retaining the root entropy scratch. If PIN setup is canceled, times out, or
loses its panel, Firmware wipes PIN and root scratch and leaves persistent state
`unprovisioned`.

Only after the repeated PIN matches does Firmware enter `pin_committing`, keep
the PIN panel active with a non-interactive processing overlay, then store the
binary root entropy, store the active default-reject policy, store the salt +
PIN verifier, persist `provisioning.state = provisioned`, and wipe volatile
scratch. Firmware defers the storage step until after the processing overlay
has had a render turn, so the user sees that input is locked while setup is
being persisted. If root material, policy, PIN verifier, or state persistence
fails, Firmware rolls back persistent setup material where possible, wipes
volatile scratch, and must not report `provisioned`.

The backup phrase is backup-ready only while its backup phrase setup panel
is still active and not expired. If that panel is removed or replaced, Firmware
wipes or invalidates the volatile phrase so a subsequent backup confirmation cannot
confirm material whose setup UI is gone. Display power state is not part of
this security state: screen/backlight sleep does not invalidate scratch by
itself, and Agent-Q UI wakes the display before showing setup material.

While the phrase display or PIN setup panel is active, `get_status` remains
available and reports `device.state = busy`. Both device-local setup panels have
finite lifetimes; expiry clears the setup panel and wipes volatile scratch.

The device-local Cancel button wipes volatile setup scratch and leaves the
persistent state `unprovisioned`. If display expiry, UI replacement, or another
failure removes the panel, Firmware must wipe scratch and the user must start
the local setup flow again.

This DEV_PROFILE provisioning flow provides read-only `get_accounts`,
device-local mnemonic import, and the source signing paths described in the
implementation status, but it remains separate from USER_PROFILE secure
provisioning. Current-schema policy updates are a separate provisioned-state
proposal flow, not part of provisioning. USER_PROFILE signing
material remains blocked by the security-profile gates in
`docs/SECURITY_MODEL.md`: secure firmware profile, encrypted storage, verified
RNG readiness, destructive hardware rehearsal, and hardware smoke.

No destructive reset or reprovisioning protocol request is implemented.
StackChan CoreS3 source implements settings actions as normal device-local UX
from the `provisioned` state. The Change PIN action verifies the current stored
PIN, accepts and repeats a new 6-digit PIN, stores only the replacement
salt/verifier, and returns to Settings; no root material is changed and no PIN is
sent over USB. Reset uses the same Settings entry point: a Reset menu action,
stored PIN verification, root material wipe, active policy wipe, PIN verifier
wipe, signing authorization mode wipe, approval history wipe, policy-update
terminal marker wipe, session cleanup, human approval input mode setting wipe, and
`unprovisioned` persistence.
Firmware writes an internal reset-pending marker before destructive wipe starts,
so boot can resume an interrupted reset wipe. PIN failure, timeout, or cancel
leaves existing material and settings intact. Wrong reset PIN attempts use a
RAM-only short lockout shared with connect and Settings PIN verification; it is
not cleared by closing and reopening a local PIN flow. Power cycling clears it.
The same destructive wipe machinery is also used by the StackChan CoreS3
device-local error-state erase recovery. That path is PIN-less because the
stored PIN verifier may be unreadable, but it still requires on-device
destructive confirmation, cannot read or export material, and is not exposed as
a USB, host process, or MCP import request.

## Current Implementation Summary

StackChan CoreS3 DEV_PROFILE source implements provisioning status reporting,
device-local setup entry, BIP-39 backup phrase display with volatile wipe and
no host exposure, device-local mnemonic import with checksum validation,
persistent root material, active policy, local PIN verifier, signing
authorization mode storage, Sui Ed25519 account derivation, and read-only
`get_accounts`.

Provisioning is not signing readiness. Policy changes use the Firmware-owned
`policy_propose` proposal flow for current-schema active policy changes.
`sign_transaction` is a single request whose Firmware-local signing mode
selects policy evaluation or user confirmation as the authorization gate.
Policy update remains a proposal flow, not a direct state setter: the host
process and Admin may submit a bounded proposal, but Firmware validates it,
requires device-local approval, and commits it through rollback-safe storage.
Sui `sign_personal_message` is source-wired for user authorization mode only;
policy facts and rules for personal-message signing are not implemented.
Sui transaction parsing is bounded and offline. Parser facts may be available
for broader programmable transactions, but parser success is not signing
authorization. Sui `sign_transaction` policy mode returns a policy rejection for
valid transactions outside the current automatic signing contract, and signs
only current-contract GasCoin-derived proven-SUI split-result transfer transactions with a matching
bounded `sign` rule. Full Admin policy editing beyond the
current policy proposal template and USER_PROFILE secure provisioning are not
implemented.

## Completion Criteria

Provisioning is complete only when:

- Firmware distinguishes unprovisioned and provisioned devices.
- New mnemonic generation happens on the device.
- Import is clearly separated from generation.
- Host-assisted import is labeled weaker than device generation.
- Generated material is wiped on cancel.
- Confirmed material is stored only in Firmware local storage.
- Export is unavailable after provisioning.
- The host process receives only public key/address data.
- DEV_PROFILE and USER_PROFILE setup are documented separately.
