# Agent-Q Security Model

This document is the source of truth for Agent-Q's threat model, device
profiles, signing-material lifecycle, firmware-integrity requirements,
policy-update authorization, and the acceptance gates a device must pass before
it may be called a locked user device.

It describes a **target** security model. Most of it is not implemented yet.
Section 2 states exactly what exists today. Every "must", "rejects", or "after
lock" statement elsewhere is a requirement for unfinished work, not a
description of current behavior.

This document does not restate the product boundary or the wire protocol. See
[../README.md](../README.md) for product context, [../specs/PROTOCOL.md](../specs/PROTOCOL.md)
for the Gateway-Firmware contract, [PROVISIONING.md](PROVISIONING.md) for
first-install signing-material setup, and [../AGENTS.md](../AGENTS.md) for the
contributor operating rules.

## 1. Scope

Agent-Q isolates signing authority and policy from the agent runtime. A
host-side Gateway relays requests; a separate device (Firmware) holds signing
material and policy and decides whether to sign or reject.

```text
Agent-Q isolates signing authority and policy from the agent runtime.
Agent-Q is not a secure-element hardware wallet.
Agent-Q does not claim Ledger-grade physical extraction resistance.
```

## 2. Implementation Status

This section is first on purpose. A security document must not make planned work
look implemented.

Implemented today:

- USB device discovery, status handshake, and identification.
- Gateway-local device selection and registry (labels, purpose routing).
- A connect/disconnect runtime session held in Firmware RAM after
  material-backed `provisioned` state. The session does not authorize signing.
- Device-local approval on the StackChan CoreS3 target for `connect`. The
  default is local 6-digit PIN entry on the device; a local setting can switch
  connect approval to the physical Confirm path after PIN verification.
- A material-backed provisioning state on the StackChan CoreS3 target. It
  reports `provisioned` only when the persisted state, valid DEV_PROFILE root
  entropy blob, committed active policy record, and local PIN verifier all
  exist. This is not signing readiness and stores no account data. The current
  build stores that DEV_PROFILE root entropy, active policy record, and PIN
  verifier in ordinary NVS; Secure Boot, Flash Encryption, and NVS Encryption
  are not configured.
- A DEV_PROFILE recovery phrase setup path in StackChan CoreS3 source. It can
  generate BIP-39 root entropy into RAM from an Agent-Q CSPRNG seeded from
  early boot entropy, display only up-to-4-letter word prefixes on the device,
  accept device-local BIP-39 recovery word entry with checksum verification,
  require a local 6-digit PIN entry/repeat after backup confirmation or
  successful recovery verification, store root entropy plus a salt + PIN
  verifier after the PIN matches, and wipe volatile scratch on local cancel,
  confirmation, display expiry, PIN setup timeout, or failure. Firmware build
  verification is required for each change. Hardware smoke coverage exists for
  StackChan CoreS3 Generate setup, PIN entry, and Recover entry.
  This is not USER_PROFILE key provisioning.
- Source-level local settings paths for provisioned StackChan CoreS3 devices.
  They are device-local UX only: Change PIN verifies the stored PIN and replaces
  only the local PIN verifier after repeated new PIN entry, and Reset verifies
  the stored PIN before root material wipe, active policy wipe, PIN verifier
  wipe, signing authorization mode wipe, approval history wipe,
  policy-update terminal marker wipe, connect-approval setting wipe, session
  cleanup, and return to `unprovisioned`.
  Firmware records an internal reset-pending marker so boot can resume an
  interrupted reset wipe. Host-triggered reset/debug protocol paths are
  intentionally not implemented. StackChan CoreS3 source also uses this
  destructive wipe machinery for a device-local, PIN-less, erase-only recovery
  from material/state consistency `error`, because the stored PIN verifier may
  be unreadable. That path cannot read, repair, unlock, or export material and
  is not exposed as a host-triggered recovery API. Hardware smoke is still
  required after reset or error-recovery UI/state changes.
- Read-only Sui account and public-key discovery over an approved runtime
  session. Firmware derives public identity from the DEV_PROFILE root entropy
  on demand and does not return mnemonic, seed, entropy, or private key
  material. Targeted hardware verification remains required after setup,
  session, or material-storage changes.
- A common firmware policy evaluator and a StackChan CoreS3 DEV_PROFILE active
  policy provider. The current product flow installs the default-reject policy,
  while the target stores the committed active policy as a canonical binary
  record in ordinary NVS and can load canonical current-schema policy records
  through its internal storage boundary. Firmware reads a public summary through
  `policy_get`, consumes that active policy only when the Firmware-local signing
  authorization mode is `policy`, rejects broad, multi-rule, and
  multi-recipient sign policies that the current device-local policy review
  cannot show clearly, and exposes policy update authorization only through the
  Firmware-owned `policy_propose` proposal flow. Policy actions do not authorize
  user-mode signing.
- A Gateway-served local Admin Page for read-only device metadata and the
  current policy proposal template. It uses the same Gateway core
  boundary as MCP and is not a policy authority.
- A bounded persistent approval-history read path. The current StackChan CoreS3
  target stores Firmware-authored signing confirmation/terminal metadata for
  `sign_transaction` and user-mode `sign_personal_message`, plus recordable
  terminal metadata from `policy_propose`. History does not store raw txBytes,
  decoded transactions, raw policy documents, full rule content, session ids,
  request ids, gateway names, PINs, secret material, or full policy documents.
  Local reset and error-state erase recovery wipe the history.
- The unified `sign_transaction` path has `source-wired-not-product-active`
  status for bounded Sui restricted transfers. Firmware derives the facts and
  account binding from `txBytes` and stored material, reads its device-local
  signing authorization mode, selects the policy or user signing gate, requires
  history before signing, emits terminal metadata, and owns cleanup. Policy
  mode evaluates active policy and signs after policy authorization with
  speech-bubble status notifications; user mode shows clear-signing review and
  requires local PIN confirmation. Requests cannot choose the authorization
  mode.
  Current-tree transaction positive/reject/timeout/session-loss hardware smoke
  remains pending; product-active status is not claimed.
- The `sign_personal_message` path has `source-wired-not-product-active` status
  for bounded Sui personal-message bytes. Firmware accepts it only in user
  authorization mode, uses clear-signing review and local PIN confirmation, and
  fails closed in policy mode because policy facts and rules for this method are
  not implemented. Current-tree personal-message hardware smoke and LVGL visual
  evidence remain pending; product-active status is not claimed.
- An Ed25519 signing self-test that generates a temporary seed at runtime, signs
  a fixed test message, and wipes the seed. There is no persistent key.

Designed but not implemented (do not treat as present):

- USER_PROFILE persistent signing keys and on-device key generation.
- Host-assisted key import.
- USER_PROFILE first-install mnemonic generation or import.
- zkLogin signing material.
- USER_PROFILE policy storage and policy update authorization.
- Arbitrary Sui transactions, policy-authorized Sui personal-message signing,
  and other chains.
- Full Admin policy editing beyond the current policy proposal template.
- USER_PROFILE / OWNER_PROFILE secure provisioning.
- Secure Boot, Flash Encryption, and NVS Encryption setup flow.

Platform capabilities this model relies on (ESP32-S3):

- Secure Boot v2 (signed bootloader and application).
- Flash Encryption.
- UART ROM Download Mode restriction or disable.
- Anti-rollback via the application `secure_version` and eFuse.
- eFuse-backed, write-once security configuration.

Current firmware build: the StackChan target applies an Agent-Q overlay onto a
pinned StackChan source and runs `idf.py build`. It configures no secure profile
and burns no eFuse.

## 3. Security Goals

Agent-Q protects two assets:

```text
1. Signing material
2. Policy
```

Policy is protected at the same level as keys. If an agent can change policy, it
can make otherwise-restricted signing material usable, which bypasses key
protection. Protecting the key without protecting the policy is not protection.

Goals:

- Keep signing material and policy outside the agent runtime and the host.
- After a device is locked into USER_PROFILE, prevent any unsigned or
  unauthorized firmware from becoming the signer.
- Keep development easy and reversible; make user security explicit, locked, and
  hard to reverse.

## 4. Non-Goals

Agent-Q does not claim:

- Secure-element hardware-wallet security.
- Ledger-grade physical extraction resistance.
- Cold-wallet-grade protection.
- Secure-element-backed attestation.
- Protection against all physical or laboratory attacks.

Agent-Q also does not verify the meaning or origin of a request:

- It does not verify that a signing request reflects user intent.
- It does not detect prompt injection, a compromised agent, or a compromised
  host.
- It cannot observe what happened inside an agent, application, or host before a
  request was created.

Firmware policy constrains risk through explicit automatic rules such as
allowlists, spending or rate limits when their facts are implemented, and
rejection, but it cannot judge why a request was created. Device-local
confirmation is a separate Firmware-owned gate, not a policy action or policy
escalation path. This restates a non-negotiable boundary from
[../AGENTS.md](../AGENTS.md).

## 5. Trust Boundaries

This is the security-relevant summary; the full roles are in
[../specs/PROTOCOL.md](../specs/PROTOCOL.md) and [../README.md](../README.md).

Gateway (host):

- Local Gateway process with stdio MCP tools and a local Admin Page sharing one
  Gateway runtime session owner.
- Transport and local coordination surface.
- Holds no signing keys.
- Makes no signing or policy decision.

Firmware (separate device):

- The signing authority.
- Stores signing material and policy locally.
- Evaluates each request.
- Rejects unavailable or policy-disallowed requests, and performs implemented
  sensitive actions only after the required Firmware-owned device-local
  approval.

Agents, MCP clients, the Admin Page, and CLI input:

- Request sources only. They are never authority.

Device-local approval gates `connect` / session establishment and sensitive
policy-write proposals. A connection session alone does not authorize signing.

`sign_transaction` has one public request shape and two internal authority
gates. Firmware chooses the gate from device-local signing authorization mode;
requests, adapters, and host callers cannot choose it.

- Policy mode evaluates the active policy for transaction signing. A policy
  reject is terminal and must not fall back to user confirmation.
- Policy mode treats policy authorization as sufficient for signing after the
  required policy history record, with speech-bubble status notifications
  instead of per-request device-local confirmation.
- User mode uses device-local clear-signing review and local PIN confirmation
  for the bounded request.
- User mode confirmation does not prove the request came from a trustworthy
  host, dapp, provider, agent, or upstream user intent. The runtime models local
  PIN confirmation and does not reuse the connect-only PIN setting as the
  signing confirmation policy.

`sign_personal_message` is a separate Sign API method for bounded Sui
personal-message bytes. Current source accepts it only in user authorization
mode, where Firmware performs clear-signing review and local PIN confirmation.
Policy authorization mode fails closed for this method because policy facts and
rules for personal-message signing are not implemented.

Policy actions must not bridge these models. A policy document may use only
action values accepted by the current schema. Any other action value is invalid
input and is rejected during validation without named compatibility branches,
reserved paths, migrations, or hidden conversion into another request type.

## 6. Device Profiles

These three profile names are Agent-Q terms, defined here.

DEV_PROFILE - the default development path:

- Free, reversible flashing and debugging.
- Test signing material only; no real assets.
- No Secure Boot or Flash Encryption requirement.
- Current StackChan CoreS3 DEV_PROFILE root entropy persistence uses ordinary
  NVS unless the platform build is separately configured for encrypted storage.
- The current StackChan CoreS3 local PIN verifier is also stored in ordinary
  NVS. It is a local UX gate for connect approval when enabled, settings
  changes, local reset, the current policy-update proposal flow, and sensitive
  local writes, not root material encryption or physical extraction defense.
- Makes no security claim. Tools and docs must show a "do not use with real
  assets" warning.

USER_PROFILE - a locked device for real signing material and real policy:

- Runs only signed firmware (Secure Boot v2).
- Anti-rollback via `secure_version` / eFuse.
- Flash Encryption in release mode.
- NVS Encryption for key/policy storage.
- JTAG/debug disabled; ROM Download Mode restricted or disabled.
- Real signing material is generated only after these protections are active
  (section 10).
- Locking is hard or impossible to reverse.

OWNER_PROFILE - a user-controlled trust root:

- The owner controls the firmware signing key and registers its public
  key/digest at provisioning.
- Only owner-signed firmware runs.
- Losing the owner key can permanently brick the device: signed updates are no
  longer possible.
- Security reduces to the owner's key hygiene.

Provisioning into USER_PROFILE or OWNER_PROFILE is explicit, shows
irreversible-operation warnings, and must be rehearsed on sacrificial hardware
first (section 15).

## 7. Signing Material

Agent-Q protects everything that can produce a signature, not only a single
private key.

Common rules, once provisioned into a locked device:

- No export path for signing material.
- Only the public key/address is exposed to Gateway.
- Only signatures leave the device.
- No raw private-key read, no `read_memory`, no debug command.
- Storage uses encrypted NVS under Flash Encryption.

Kinds:

Device-generated key (preferred):

- Generated inside the locked device, only after USER_PROFILE protections are
  active.
- The private key never existed outside the device.
- The first target chain signs with Ed25519 (Sui); the protocol stays
  chain-agnostic through shared Sign API methods such as `sign_transaction` and
  `sign_personal_message`.

Imported key (weaker):

- The host saw the key during import, so its confidentiality is already weaker
  than a device-generated key.
- No export after import.
- Not exposed through a normal MCP path; not the default for real assets.

zkLogin material (not implemented; a different trust model):

- It involves an external ceremony (OAuth JWT, ZK proof, salt, and an ephemeral
  key bounded by a `maxEpoch`) with off-device parties.
- It must not be described as an ordinary device-generated private key.
- Its lifecycle (expiry, refresh, replay) must be defined separately before it
  ships.

## 8. Policy Protection

Policy decides when signing material may be used. Firmware stores and enforces it
as the source of truth. Gateway and the Admin Page may relay a policy-update
request but are not authority.

Default policy posture (design):

- Deny by default.
- Reject unsupported request types.
- Reject unsupported parser features.
- Reject replayed requests.
- Reject stale or expired requests where enforceable (section 13).
- Reject when a rate or amount limit is exceeded.

Policy-update authorization models, chosen per target capability:

Provisioning-only:

- Strongest minimal model. Policy is set at provisioning; there is no runtime
  update. Changing it requires re-provisioning.

Password-authorized:

- Usable on a device without buttons or a display.
- Weaker if the host is compromised; treat it as a local-convenience boundary,
  not a defense against a compromised host.
- The verifier must be device-side (salt + KDF verifier). Gateway must not store
  the password; Firmware must not store a plaintext password.
- Repeated failures must be rate-limited, delayed, or locked out.

Button-confirmed:

- Confirms that a change is happening but cannot show the full diff. Pair it with
  a short code/hash compared against the Admin Page.

Display-confirmed:

- Shows a policy diff/summary on the device; the user approves or rejects
  locally. Strongest device-confirmed model; can avoid a host-held password.

A setup password is not required when the device has trusted local input and can
present the change for local approval. A device without trusted local input must
use either a password model (with the host-compromise limits above) or a
provisioning-only model.

Policy-update contract:

- A policy update is a proposal submitted to Firmware, not a state setter.
- Gateway, Admin, CLI, and MCP clients are request sources only. They may relay a
  proposal but do not authorize or apply it.
- Firmware validates the bounded policy document, shows device-local approval,
  and commits only after approval.
- Firmware must accept only policy actions that the current schema allows and
  the current runtime can enforce. Other action values are invalid input and
  must not be stored as dormant behavior.
- The first wire format is JSON inside the existing protocol envelope.
  Firmware must canonicalize the accepted policy into a bounded binary policy
  record before storage and hash calculation; raw JSON is not the active policy
  storage format.
- The active policy store must preserve the old policy until the new policy is
  fully written, validated, and selected as active. A durable pending-write
  marker may identify an interrupted inactive-slot write that can safely roll
  back to the previous committed policy. The metadata flip is the commit point:
  after that point, cleanup failure is not reported as a failed write because
  the new policy is already authoritative. Stale pending markers that exactly
  match the selected committed policy are ignored by active-policy selection,
  and stale commit metadata is removed before its slot or metadata key is
  reused. Each write must end as applied, previous policy proven unchanged, or
  persistent-material consistency error. Firmware recognizes only the current
  tracked active-policy storage layout as product state. Invalid commit metadata
  without a matching pending marker, or pending targets that overlap but do not
  exactly match the selected active material, is ambiguous storage state and therefore a
  persistent-material consistency error.
- DEV_PROFILE slot selection is not rollback protection. USER_PROFILE policy
  storage requires secure anti-rollback or monotonic commit protection before it
  can claim rollback resistance.
- Policy update history may record metadata such as result, policy hash, rule
  count, and highest-risk action, but must not record raw policy documents,
  complete rule content, session ids, request ids, gateway names, PINs, mnemonic
  text, seed, or private key material.
- Once a policy update reaches the post-commit terminal phase, Firmware
  must persist a small policy-update terminal marker until both the policy commit
  and required history record are durable. A leftover terminal marker at boot is
  persistent-material inconsistency, not a normal `provisioned` state. Local
  reset and error-state erase wipe the marker with the rest of the policy
  material.

## 9. Firmware Integrity

Firmware integrity is the root requirement, above key and policy protection.
Malicious firmware that runs on the device can read stored signing material, add
an export command, remove policy checks, or sign without limits.

Two attacks to defend against:

```text
1. Replacing Agent-Q Firmware with a hacked image that exports keys.
2. Installing another bootable image (OTA, recovery, factory) that reads the
   same signing storage.
```

Defense goal:

```text
In USER_PROFILE, the device must reject any unsigned bootable image, whether it
replaces the current firmware or is added as another bootable slot.
```

Required controls:

- Secure Boot v2.
- Anti-rollback via `secure_version` / eFuse.
- Signed bootloader and application images.
- A partition/update policy that covers every bootable slot.
- Flash Encryption in release mode.
- NVS Encryption for key/policy storage.
- JTAG/debug disabled.
- ROM Download Mode restricted or disabled.

Limit:

- Flash Encryption protects flash at rest, but code running on the device can
  read decrypted data. The "no export" guarantee therefore rests on Secure Boot
  (only signed code runs), debug being off, and download mode being restricted,
  not on hardware key isolation.

Remaining trust:

- Even with all controls, trust still depends on the Secure Boot keys, a signed
  bootloader and partition table, the anti-rollback configuration, and the
  maintainer or owner never signing a firmware image that can export or bypass
  signing material.

## 10. USER_PROFILE Provisioning Order

Order matters. Generating or importing key material before the protections are
active can write the key to unencrypted flash or run it under replaceable
firmware.

```text
1.  Build the trusted, signed firmware (this same image performs key
    generation in the later steps).
2.  Enable Secure Boot v2.
3.  Enable Flash Encryption (release mode).
4.  Enable the anti-rollback secure_version policy.
5.  Enable NVS Encryption.
6.  Restrict or disable ROM Download Mode.
7.  Disable debug / JTAG paths.
8.  Boot the signed key-generation firmware (only signed firmware boots now).
9.  Verify hardware RNG readiness / entropy source.
10. Generate signing material on the device.
11. Store signing material in encrypted local storage.
12. Expose only the public key / address.
```

Hard rule:

- Do not generate or import real signing material before USER_PROFILE
  protections are active.

Entropy gate:

- Signing-material generation must be gated on a verified hardware RNG entropy
  source. Weak or unverified entropy is a key-compromise condition, not a
  warning.

The exact `espefuse` / `menuconfig` sequence for steps 2 to 7 is an
implementation detail to fix and validate on sacrificial hardware (section 15).

## 11. Update And Admin Paths

The administrative, setup, and update paths are separate from signing method
calls.

Must not be reachable through a normal MCP signing path:

- Firmware update.
- Policy write.
- Factory reset or root-material wipe.
- `export_key`, `raw_sign`, `read_memory`, `debug_command`.

Allowed direction:

- Admin/update mode is separated from signing method calls.
- A policy write requires Firmware-side authorization (section 8).
- Firmware update accepts signed images only.
- Policy update proposals use a dedicated Admin/update method such as
  `policy_propose`; they must not be exposed as `set_policy`,
  `force_policy`, `clear_policy`, or another direct state-changing setter.

Enforcement today:

- The current MCP top-level tool set is constrained by exact-allowlist tests: the
  registered tools must equal a fixed set, both at definition and over the live
  transport. A new tool such as `export_key` cannot be added without failing
  those tests.
- MCP and provider-sui expose the current Sign API through different package
  interfaces for their audiences, including transaction signing and user-mode
  personal-message signing. Those adapter surfaces are not the signing
  authority. Firmware state gates, method adapters, the device-local signing
  authorization mode, active policy evaluation in policy mode, and local
  confirmation in user mode remain the boundaries. Arbitrary Sui transactions,
  policy-authorized personal-message signing, and other chains are not
  implemented. The top-level tool allowlist does not grant authority to method
  names carried inside Sign API requests; Firmware method adapters and active
  policy validation remain the method boundary.

## 12. Device Capability Tiers

Hardware determines what human confirmation is possible.

Minimal Device:

- Sign or reject only. No per-request human confirmation.

Button Device:

- Sign or reject, with limited local confirmation.

Display Approval Device:

- Can show a summary for flows that explicitly require local approval, such as
  connection establishment, policy update proposals, or user-mode
  `sign_transaction` and `sign_personal_message` signing.

The current StackChan CoreS3 target has a display and touch, so it is closest to
the Display Approval tier. "Minimal Device" describes a non-current hardware
target, not the current one.

Minimal Device risk, stated plainly:

- With no per-request approval, a compromised host or agent can obtain any
  agent-request signature that Firmware active policy allows, with no
  human in the loop. On such a device, the only limit on a compromised host is
  the Firmware policy itself.

## 13. Replay And Expiry

- Each request carries a `requestId`.
- The device needs a local monotonic counter or nonce to reject replays. It
  should be persisted in encrypted storage so a reboot does not reopen a replay
  window.
- Persisting replay state has a cost: a counter write per request causes flash
  wear, and a nonce cache needs a bounded eviction policy. Size this tradeoff
  deliberately.
- Host-supplied expiration timestamps are weak unless the device has trusted
  time. Without a trusted RTC, time-based expiry is a secondary control; the
  monotonic counter or nonce is the primary replay defense.

## 14. Release Signing

M0:

- CI builds, tests, and publishes artifacts only.
- The maintainer signs firmware locally / offline.
- A release includes the signed firmware, a manifest, and a hash.
- The local signing key is the trust root for every USER_PROFILE device. Its
  compromise is catastrophic and per-device irreversible. Protect it
  accordingly.

Long term:

- Sign with an HSM / YubiHSM / KMS.
- CI requests signing (for example via OIDC) rather than holding a key.
- The signing private key is never stored directly in GitHub Secrets.

Trust anchor:

- The manifest and SHA256 help the host identify an artifact. The device trust
  anchor is the Secure Boot key digest in eFuse. That, not the manifest, is what
  prevents malicious firmware from booting.

## 15. Required Work And Acceptance Gates

Before any device may be called a locked USER_PROFILE device, the following must
pass. None of this is implemented yet.

Build / provisioning:

- A secure USER_PROFILE build profile exists.
- A signed-firmware build path exists.
- Anti-rollback `secure_version` is configured.
- Flash Encryption (release mode) is configured.
- NVS Encryption is configured.
- ROM Download Mode is restricted or disabled.
- JTAG/debug is disabled.

Dry-run and destructive testing:

- The procedure is dry-run with virtual eFuse (`CONFIG_EFUSE_VIRTUAL`).
- The full provisioning is rehearsed on sacrificial hardware before any real
  device.
- Every irreversible eFuse step is documented.

Firmware integrity:

- An unsigned bootable image fails to boot.
- An unsigned OTA/recovery/factory image fails to boot.
- A valid signed update succeeds.
- A signed older image with a lower `secure_version` fails (anti-rollback).
- The debug/JTAG path is unavailable.
- The ROM Download Mode restriction is verified.

API boundary:

- No `export_key`, `raw_sign`, `read_memory`, or `debug_command`.
- The MCP top-level exact-allowlist test passes.
- Sign API method allowlist and negative tests cover every shipped signing
  method.

Key and policy:

- Real signing material is generated only after the USER_PROFILE lock.
- An RNG readiness check runs before key generation.
- Private-key export is unavailable.
- A policy write requires the selected authorization model.
- The password model, if used, enforces rate limit, delay, or lockout.
