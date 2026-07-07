# <Hardware Id> Required Test Template

This template defines the minimum verification rows for a Firmware target. A
target must replace each row with concrete scripts, hardware smoke evidence, or
`N/A` with the reason the capability is not implemented.

Passing tests are evidence, not completion by themselves. A target slice is
complete only when the implemented boundary is correct, verified, documented,
and free of known in-boundary debt.

## Static And Build Checks

| Requirement | Evidence |
|---|---|
| `fetch.sh` uses pinned upstream sources and does not depend on `.WORK/`. |  |
| `prepare.sh` copies only tracked overlays and pinned source dependencies. |  |
| `build.sh` completes from a clean generated tree. |  |
| Product source contains no `nvs_flash_erase` recovery path unless explicitly justified outside product firmware. |  |
| Product source contains no debug/internal-state protocol method, state setter, dump command, or test-only shortcut. |  |
| Target docs do not claim planned behavior as implemented. |  |
| Shared protocol method names, enum values, schemas, and public error codes are not target-specific. |  |
| No real hardware/user payloads, addresses, signatures, proof material, JWTs, or private material are tracked as fixtures. |  |

## Common Protocol Checks

| Requirement | Evidence |
|---|---|
| Malformed request envelope fails with shared `invalid_request`. |  |
| Unsupported protocol version fails with shared `unsupported_version`. |  |
| Unsupported method fails with shared `unsupported_method`. |  |
| Wrong-state request fails with the defined state error before irrelevant parameter validation. |  |
| `get_status` is available in every state and does not require approval UI. |  |
| `identify_device` is temporary and does not change product state. |  |
| Shared `DeviceResponse` success and failure shapes match `specs/PROTOCOL.md`. |  |
| Common method table / manifest parity is verified. |  |

## State Projection And Session Checks

| Requirement | Evidence |
|---|---|
| First-run or missing-material state projects through shared status values. |  |
| Locked state projects through shared status values and enforces `auth_unavailable` where required. |  |
| Provisioned/account-ready state projects through shared status values. |  |
| Persistent-material inconsistency projects `error` and fails closed. |  |
| `connect` creates a session only through Firmware-owned approval when no live approved session exists. |  |
| Same-link session recovery returns only the existing session and does not create or replace a session. |  |
| `disconnect` clears only matching session-scoped state. |  |
| USB removal, reset, power loss, or target-defined link loss clears volatile session and sensitive scratch. |  |
| Session-scoped methods reject missing, invalid, or stale sessions. |  |

## Local Authentication And Approval Checks

| Requirement | Evidence |
|---|---|
| Local authentication setup stores only verifier material, not raw input. |  |
| Local authentication failure increments the bounded failure state. |  |
| Lock/time-lock behavior persists according to the target's trusted-time model. |  |
| Relock clears volatile local-authentication input scratch. |  |
| Approval UI maps only to approve, reject, timeout, or UI error. |  |
| Approval cancel/reject/timeout clears pending approval scratch and returns a shared terminal result. |  |
| UI object lifetime is not the source of truth for approval, session, signing, or credential state. |  |

## Storage Safety Checks

| Requirement | Evidence |
|---|---|
| Signing key material is stored separately from mutable settings. |  |
| Settings repair never erases signing key material. |  |
| Device reset explicitly erases signing key material only through device-local destructive flow. |  |
| Unsupported current storage data fails closed instead of being accepted as product state. |  |
| Storage write failure has a defined post-failure state. |  |
| Pending storage markers cannot make stale or partial writes look successful. |  |
| Sensitive scratch is wiped after success, reject, timeout, failure, disconnect, reset, and UI loss. |  |

## Account And Credential Checks

| Requirement | Evidence |
|---|---|
| `get_capabilities` exposes only shared schemas and current capability availability. |  |
| `get_accounts` exposes only public account identity and no private material. |  |
| `credential_prepare` is session-bound and returns only public preparation material. |  |
| `credential_propose` requires the matching allowed state, payload resolution, device-local review, and local approval. |  |
| Credential activation clears or invalidates the session as specified. |  |
| Credential reject/timeout/cancel/storage error has a defined cleanup path. |  |
| Host cannot directly clear proofs or install credentials through a target-specific shortcut. |  |

## Payload Transfer Checks

| Requirement | Evidence |
|---|---|
| `payload_transfer.begin` validates session, transfer id, operation, size, digest, and timeout. |  |
| `payload_transfer.chunk` validates transfer ownership, order, bounds, and canonical base64. |  |
| `payload_transfer.finish` validates final digest and returns a session-scoped payload reference. |  |
| `payload_transfer.abort` clears only the matching transfer. |  |
| Finalized payload references are method/session scoped as required by the consuming method. |  |
| Payload scratch clears on timeout, disconnect, session loss, reset, and successful consumption. |  |
| Safe-read methods remain available only when the shared rules allow them. |  |

## Policy Checks

| Requirement | Evidence |
|---|---|
| `policy_get` reads only the current active policy through the shared schema. |  |
| `policy_propose` is a bounded proposal, not a direct setter. |  |
| Policy proposal review is Firmware-owned and device-local. |  |
| Policy commit has a defined commit point and post-failure state. |  |
| Policy reset, if implemented, is device-local and not a protocol shortcut. |  |
| Invalid policy actions fail closed without compatibility branches. |  |

## Signing Checks

| Requirement | Evidence |
|---|---|
| Signing route classification occurs before stateful signing work. |  |
| Unsupported chain returns `unsupported_chain`. |  |
| Unsupported method or type mismatch returns `unsupported_method`. |  |
| Signing rejects missing account, wrong network, invalid session, busy state, and unavailable authorization state. |  |
| Transaction signing parses bounded bytes through the shared parser before signing. |  |
| Personal-message signing signs the shared PersonalMessage intent, not raw display text. |  |
| Account binding is enforced before signing. |  |
| Policy mode and user-confirmed mode remain separate Firmware-owned gates. |  |
| Protocol requests cannot choose the signing authorization mode. |  |
| Required history is durable before returning signed success. |  |
| Signing critical section wipes payload and signature scratch after every terminal path. |  |
| Retained signing responses are scoped to the active session and request id. |  |

## Hardware Smoke Checks

Each implemented target slice must define a current-tree hardware smoke
sequence. Record the evidence path, target hardware, commit, build, flash,
manual steps, observed result, and unchecked paths.

Minimum smoke rows:

| Flow | Evidence |
|---|---|
| Boot to first visible target state. |  |
| Local setup or local-authentication setup. |  |
| Lock/relock and unlock. |  |
| Display off/on or hardware power behavior, if applicable. |  |
| USB connect approval and disconnect. |  |
| USB removal/reconnect session behavior. |  |
| Credential setup, if implemented. |  |
| Account projection, if implemented. |  |
| Policy read/update, if implemented. |  |
| User-confirmed transaction signing, if implemented. |  |
| Policy-authorized transaction signing, if implemented. |  |
| Personal-message signing, if implemented. |  |
| Error or storage-repair path, if implemented. |  |
| Device reset or destructive key erase path, if implemented. |  |

If a hardware smoke row cannot be run, the target slice remains `0` unless the
accepted boundary explicitly excludes that flow before implementation starts.
