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

- Firmware holds signing material and owns provisioning and signing decisions.
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
  -> Firmware creates a PIN-wrapped random master key
  -> Firmware encrypts and stores root material locally
  -> Firmware stores an active default-reject policy locally
  -> Firmware stores Sui account settings locally
  -> Firmware exposes only public keys / addresses
```

Rules:

- The host never receives the root mnemonic or seed.
- The mnemonic is shown only during provisioning.
- After confirmation, the mnemonic is not shown again.
- If setup is canceled, Firmware wipes the generated material.
- A device is not `provisioned` unless the encrypted keyslot and root, an active
  policy, signing authorization mode, and Sui account settings are all
  present. New setup initializes the Sui account setting to reject gas sponsors.
- The encrypted keyslot is the sole current PIN verifier. Boot unlock and each
  PIN-authorized action authenticate the same keyslot process. Boot unlock does
  not count as connect or signing approval.
- The software-encryption layer removes plaintext private material from ordinary
  NVS but does not make the six-digit PIN resistant to practical offline
  exhaustive search of a copied flash image.

### Import Existing Mnemonic

Device-local import path:

```text
user provides mnemonic
  -> Firmware validates it
  -> user enters and repeats a 6-digit local PIN on device
  -> Firmware creates a PIN-wrapped random master key
  -> Firmware encrypts and stores root material locally
  -> Firmware stores an active policy locally
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

StackChan CoreS3 has display and touch hardware. DEV_PROFILE backup phrase
generation, backup confirmation, encrypted root storage, and read-only
`get_accounts` Sui account derivation are implemented. The current setup
implementation also creates the PIN-wrapped keyslot before reporting
`provisioned`, and initializes device-local signing authorization mode to
`user`. Source/build tests cover the provisioned host process and MCP session path
through `get_accounts`, policy-decision rejection, inline and same-session
staged Sui `sign_transaction` request validation for bounded
`TransactionData::V1 -> ProgrammableTransaction` bytes, the current
`sign_transaction` policy/user gate split, and the user-mode
`sign_personal_message` implementation path.
Earlier hardware smoke covered StackChan CoreS3 local setup and PIN entry on the
plaintext predecessor schema. Current encrypted-keystore setup, reboot unlock,
and account access require current-tree hardware verification.
Local settings storage maintenance is implemented for provisioned StackChan
CoreS3 devices. The normal Settings menu exposes one destructive Device reset
action; it erases the keyslot and every encrypted private-material record and
returns the device to `unprovisioned`.
Root-preserving settings repair is
reserved for persistent-material consistency errors when encrypted root and a
valid keyslot remain. It restores recoverable mutable settings,
including zkLogin proof state, without erasing root material. Earlier hardware
smoke covered root-preserving settings repair and Device reset on the plaintext
predecessor schema. Current encrypted-keystore repair and reset require
current-tree hardware verification.
Device-local Import is implemented for DEV_PROFILE. USB, host process, and MCP mnemonic
import and host-assisted import are not implemented. Execution-effect-complete
arbitrary Sui transaction review or policy simulation is not implemented.
Automatic signing outside the bounded policy-authorized `sign_transaction` path
is not implemented.

## Chain Accounts

The root mnemonic or seed is chain-neutral. Chain adapters own their derivation
path, signing scheme, address calculation, and public key format.

Current executable chain:

- Sui

Rules:

- The host process must not derive private keys.
- Firmware returns public key/address data through `get_accounts`.
- The current Sign API implementation paths have `source-wired-not-product-active`
  status for Sui `sign_transaction` with inline or same-session staged
  transaction bytes decoded by the Firmware Sui `TransactionData::V1 ->
  ProgrammableTransaction` facts extractor, and for user-mode Sui
  `sign_personal_message`.
  Firmware reads its local signing authorization mode and selects one gate:
  policy mode validates active policy availability, request network scope,
  account binding, and Firmware-derived offline policy condition facts, then
  signs only when the active current policy has a matching `sign` policy. User
  mode uses
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
- `provisioned`: encrypted root signing material, a valid keyslot, an active
  policy, and signing authorization mode exist. A rebooted provisioned target
  still projects device state `locked` until local unlock succeeds.
- `error`: Firmware detected persistent-material inconsistency and is failing
  closed.
- `locked`: sensitive actions require local unlock.

The current DEV_PROFILE runtime implements the StackChan CoreS3 mnemonic UI flow and
persistent root material storage path. It loads and reports `provisioning.state`, but
does not persist `provisioning` during the normal create-new-mnemonic flow.
After physical backup confirmation, Firmware creates the PIN-wrapped keyslot
and encrypted BIP-39 root record in protected device-local NVS storage, stores
mutable policy and account settings in a separate
DEV_PROFILE NVS settings namespace, and only then moves to `provisioned`.
DEV_PROFILE storage with `prov_state = provisioned` but missing,
unreadable, or unsupported current active policy material, signing authorization
mode, or Sui account settings fail closed. Settings repair, Device reset, or
development flash erase is the supported recovery path according to the
remaining authority-gate material; Firmware recognizes only the current tracked
storage layout as product state. Settings repair rebuilds mutable settings and
zkLogin proof state without deleting the keyslot or encrypted root.
The keyslot and encrypted private-material records are permanent keystore
records, not part of the mutable settings schema or a compatibility path. They
must not be renamed or moved by firmware updates as a settings repair
mechanism.
If the persisted state and required material records disagree after boot or
during runtime checks, Firmware reports `provisioning.state = error`; it does
not keep reporting `provisioned` while rejecting all session APIs.

The current DEV_PROFILE runtime does not import or export root signing material.
Read-only public Sui account derivation is available via `get_accounts`.
The current Sign API implementation paths exist for Sui `sign_transaction` transaction
bytes delivered inline or through same-session staging and for user-mode
`sign_personal_message` personal-message bytes. Sui transaction bytes are
decoded by the Firmware Sui `TransactionData::V1 -> ProgrammableTransaction`
facts extractor. Unsupported versions, unsupported transaction kinds,
malformed bytes, out-of-range command references, and transactions whose
minimum sender or gas owner facts cannot be extracted fail closed. The parsed
sender must match the active account. The parsed gas owner must also match unless
the active account's Sui account setting accepts gas sponsors.
Valid account-bound transactions whose offline review facts are incomplete may
enter the explicit user-mode blind-signing path; policy mode signs only when
the active current policy has a matching `sign` policy over complete offline
condition facts, and otherwise rejects. Product-active claims still depend on the
target evidence tracked in `docs/IMPLEMENTATION_STATUS.md`.
Current StackChan CoreS3 source can generate a BIP-39 backup
phrase as RAM scratch, display its up-to-4-letter word prefixes on device in a
3-column by 4-row grid, and wipe scratch on confirm, cancel, timeout, failure,
or display expiry. Three-letter BIP-39 words are displayed as the full word.
This remains a development target rather than a hardware-backed release
profile. Firmware must not set `provisioned` unless the keyslot and encrypted
root, an active policy, and signing authorization mode exist in
device-local storage.

Current DEV_PROFILE state transitions:

```mermaid
stateDiagram-v2
    [*] --> Unprovisioned: boot default or stored state
    Unprovisioned --> Unprovisioned: local setup opens phrase display
    Unprovisioned --> Unprovisioned: local Confirm, PIN entry active
    Unprovisioned --> Provisioned: matching PIN repeat, keyslot + encrypted root + policy + signing mode stored
    Provisioned --> Locked: reboot with valid current records
    Locked --> Provisioned: local PIN opens keyslot and authenticates mandatory records
    Locked --> Locked: wrong PIN
    Unprovisioned --> Unprovisioned: local Cancel/timeout/failure, scratch wiped

    Unprovisioned: no encrypted root, keyslot, active policy, or signing mode
    Unprovisioned: optional volatile mnemonic/root/PIN setup scratch only
    Locked: keyslot and encrypted records persist; only status, local unlock, and destructive recovery are available
    Provisioned: encrypted root, keyslot, active policy, and signing mode stored and unlocked; session-scoped APIs may proceed through their own gates
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
root entropy in an authenticated encrypted record, create the PIN-wrapped
master-key slot, store the active default-reject policy, persist
`provisioning.state = provisioned`, and wipe volatile scratch. Firmware defers
the storage step until after the processing overlay has had a render turn, so
the user sees that input is locked while setup is being persisted. If the
encrypted root, keyslot, policy, or state commit fails, Firmware rolls back
persistent setup material where possible, wipes volatile scratch, and must not
report `provisioned`.

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
from the unlocked `provisioned` state. The Change PIN action authenticates the
current keyslot with the current PIN, accepts and repeats a new 6-digit PIN,
atomically rewraps the unchanged master key with a fresh salt and nonce, and
returns to Settings. It does not rewrite the encrypted root or send a PIN over
USB.

Device reset is the normal destructive device-local Settings path. It erases
the keyslot and encrypted private-material records, active policy, signing
authorization mode, Sui account settings, Sui zkLogin proof material, approval
history, policy-update terminal marker, human approval input mode setting,
active runtime session, and returns the device to `unprovisioned`. Firmware
writes an internal storage-action marker before committing Device reset or
internal settings repair so boot can resume an interrupted action without using
a partition erase. A pending marker keeps control of the next recovery
operation; a pending Device reset cannot be reclassified as settings repair
because a keyslot and encrypted root still read as present. PIN failure,
timeout, or cancel leaves existing material and settings intact.

The StackChan CoreS3 device-local error-state recovery path chooses settings
repair when the current keyslot and encrypted root remain structurally valid,
and chooses Device reset when the authority gate is unavailable. Repair first
requires successful local PIN unlock, preserves the keyslot and encrypted root,
restores recoverable mutable settings to current defaults, clears Sui zkLogin
proof material, approval history, policy-update terminal marker, and the active
runtime session, and keeps `provisioning.state = provisioned`. Device reset
recovery has no PIN requirement because the keyslot or encrypted root may be
unreadable, but it still requires on-device destructive confirmation, cannot
read or export material, and is not exposed as a USB, host process, or MCP
request.

## Current Implementation Summary

StackChan CoreS3 DEV_PROFILE source implements provisioning status reporting,
device-local setup entry, BIP-39 backup phrase display with volatile wipe and
no host exposure, device-local mnemonic import with checksum validation,
an authenticated encrypted root record and PIN-wrapped master-key slot, active
policy and signing authorization mode storage, Sui Ed25519 account derivation,
and read-only `get_accounts`. A valid provisioned device boots locked and must
open its keyslot locally before account, signing, or private local-transport use.

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
authorization. Sui `sign_transaction` policy mode authorizes only matching
active current policy entries over complete Firmware-derived offline condition
facts, and rejects missing, incomplete, unmatched, or reject-matched policy
coverage. Admin policy authority and USER_PROFILE secure provisioning are not
implemented. Admin may submit current-schema policy proposals, but Firmware owns
validation, device-local approval, commit, policy evaluation, and signing
decisions.

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
