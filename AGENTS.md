# AGENTS.md

This file is the root operating contract for coding agents working in this
repository. Read it from disk before every task.

Behavioral guidelines reduce common LLM coding mistakes. Project-specific rules
are included only where they affect how this repository should be edited.

Tradeoff: these guidelines bias toward caution over speed. For trivial tasks,
use judgment.

## Minimal Product Context

Agent-Q separates AI agent execution from signing authority.

The goal is to let agents request signatures through a local Gateway while a
separate device keeps keys and policies, evaluates each request, and decides
whether to reject or proceed according to the currently implemented policy and
request type. Firmware-owned device-local approval is a separate requirement
for implemented sensitive flows such as connection establishment and policy
update proposals. Do not describe signing policy as requiring device-local
approval unless the current protocol explicitly implements that model.

Product context lives in `README.md`. The shared communication contract between
Gateway and the software running on the device lives in `specs/PROTOCOL.md`.

Terms used in this document:

- Gateway means the local server process that exposes MCP and web endpoints.
- MCP means Model Context Protocol.
- Firmware means the software running on a separate signing device.
- Admin Page means the local web UI served by Gateway.

Write documentation so a new agent or human can understand it without prior chat
context.

Avoid project-made terminology when an ordinary industry term works. If a
project term is unavoidable, define it at first use and state exactly what it
does and does not mean.

## Product Boundary

Non-negotiable boundaries:

- Agent-Q Gateway is a local MCP server and local web server.
- Agent-Q Gateway must not store signing keys.
- Agent-Q Gateway must not make signing or policy decisions.
- Admin is a Gateway capability, not a separate product area.
- Agent-Q Firmware is the signing authority.
- Agent-Q Firmware stores keys and policies locally.
- First connection and sensitive write actions must pass Firmware-owned
  device-local approval state gates.
- Firmware request UI must preserve the device's current mode or screen whenever
  possible. Use temporary identification, approval, and result layers instead of
  forcing a dedicated Agent-Q mode for normal requests.
- External MCP clients, AI agents, Admin Page requests, and CLI inputs are
  requests, not authority.
- Agent-Q cannot observe or verify what happened inside an agent, application,
  or host environment before a signing request was created.
- Agent-Q must not claim to detect user intent, prompt injection, compromised
  agent behavior, or any other upstream cause of a signing request.
- Treat all external requests as untrusted inputs. Firmware policy must evaluate
  request contents and constrain risk through explicit automatic rules such as
  allowlists, spending limits, rate limits, and rejection. Device-local approval
  is a separate request/state gate, not a policy action or policy escalation
  path.
- Future signing work must keep delegated policy requests and device-confirmed
  requests separate. A device-confirmed request means Firmware requires
  device-local confirmation for a bounded request; it does not prove the host,
  dapp, provider, agent, or user intent that produced the request.
- Current policy documents may contain only current-schema action values. Any
  other action value is invalid input and must fail closed without named
  compatibility branches, reserved paths, or hidden conversion into another
  request type.
- Do not present planned signing, policy, chain, transport, hardware, or Admin
  behavior as implemented behavior.
- Do not create separate chain-specific product APIs. Chains must be exposed as
  supported methods in the shared protocol.
- Before a public release, do not add automatic backward-compatibility,
  migration, or named handling for previous Firmware storage, protocol, policy,
  or approval-history formats unless the user explicitly approves that product
  requirement. Firmware should know only the current tracked layout.
  Unknown or unsupported persistent data must not become product state; it
  should fail closed through the existing current-state gates and recover
  through device-local erase, reprovisioning, or a development flash-erase
  workflow. Version or format fields are allowed only to identify and accept the
  current schema or reject unsupported data, not to quietly accept it.

## 1. Start From Evidence

Do not work from imagination or unchecked assumptions.

Before editing:

- Read the relevant files from disk.
- Inspect the current repository state.
- Check package metadata, scripts, lockfiles, source code, and docs before
  making claims about them.
- Keep investigation-only source checkouts, downloaded references, vendor
  investigations, and other evidence sources under `.WORK/`.
- Firmware build dependency caches may use ignored, task-specific directories
  such as `.firmware-cache/` when the source repositories and commits are pinned
  in tracked files.
- Use `.WORK/` only as local evidence and scratch space. Do not make tracked
  build scripts, user instructions, or CI workflows depend on `.WORK/` paths.
- Treat README text and comments as hints. Source files, package metadata, and
  direct command output win.
- If evidence is missing, say what is missing and gather it before editing.

Do not rely on memory, previous turns, or summaries as a substitute.

## 2. Think Before Coding

Do not assume. Do not hide confusion. Surface tradeoffs.

Before implementing:

- State assumptions explicitly when they affect architecture, security, public
  API, protocol meaning, or product boundaries.
- If multiple interpretations exist, present them instead of picking silently.
- If a simpler approach exists, say so.
- Push back when the requested shape appears overcomplicated or inconsistent
  with the repository direction.
- If something is unclear and a wrong assumption would be costly, stop and ask.

## 3. Scope And Planning

Treat work as non-trivial when it touches multiple files, changes protocol
behavior, changes product-boundary docs, creates package structure, affects
public commands, follows an accepted plan, revisits incomplete work, or responds
to a previous incorrect completion claim.

For non-trivial work:

1. State the current task goal.
2. Identify the boundary that must not be crossed.
3. Inspect affected files, docs, protocol messages, commands, and failure paths
   before editing.
4. Establish a specification baseline from the user request, accepted plan,
   promised behavior, and required cleanup found during investigation.
5. Compare reasonable implementation directions when architecture, protocol,
   security, public API, or product authority is affected.
6. Map each baseline requirement to an implementation surface and verification
   point.
7. Implement the complete change for the verified boundary.
8. Re-check the affected boundary from product purpose, files, docs, protocol,
   tests, and user flows.

For non-trivial work that touches protocol behavior, device state, Firmware
state storage, Gateway/MCP API surface, provisioning, accounts, policy, signing,
or product-boundary documentation, the plan must also classify the affected
device states before implementation starts. Use `docs/STATE_MODEL.md` as the
baseline for state names and state-gated behavior.

A state-scoped plan must state:

- the current/source device state;
- the target device state, if the work changes state;
- each state owner, separating persistent device state, volatile sensitive
  scratch state, pending approval state, and UI/display state when more than one
  exists;
- APIs that are allowed in each affected state;
- APIs that must remain unavailable in each affected state;
- the authority that enforces the rule: Firmware or Gateway;
- the UI requirement: silent handling, notification, or physical approval;
- persistence and wipe requirements;
- transition triggers, guards, side effects, failure behavior, and cleanup for
  each affected state transition;
- verification for each affected state.

Do not implement a new API, state transition, account path, signing path, policy
path, or provisioning step unless its allowed and forbidden states are
explicitly classified.

Gateway may hide unavailable operations, but Firmware must enforce device-state
gates.

External APIs must not directly command Firmware state transitions. A protocol
request may read state or submit bounded input for Firmware to evaluate, but it
must not be shaped as a direct state setter.
Firmware state transitions must be internal consequences of Firmware-owned
conditions such as current state, validated input, stored material consistency,
policy evaluation, physical input, successful persistence, timeout, or failure
cleanup. APIs then behave according to the resulting state; they do not create
authority to force that state from outside.

Do not add convenience APIs, debug protocol messages, host-triggered setup,
host-triggered reset, diagnostic display commands, or state-changing shortcuts
for tests or demos. If a hardware test needs special setup, use a development
firmware build or re-flash workflow for that test. The tested behavior itself
must still enter through the normal product UX and normal protocol surface.

Do not use UI object lifetime as the source of truth for security, provisioning,
signing, account, policy, session, or sensitive scratch state. UI may display,
request, or mirror state, but explicit state variables owned by the responsible
module must decide whether an operation is allowed and what cleanup is required.

For state-scoped APIs, validate the protocol envelope enough to identify the
operation, then check the source-state and setup-step guards before validating
operation parameters that are irrelevant when the state is wrong. A request in
the wrong state should fail with the state error defined by the protocol instead
of a parameter error caused by an operation that is unavailable in that state.

When a transition can fail partway through, define the post-failure state
explicitly. Sensitive volatile scratch must either remain valid and visible for
the next allowed step, or be wiped and made impossible to confirm or use. Do not
leave hidden scratch, stale approvals, or responses that claim a transition
succeeded after the state that justifies it was cleared.

Do not interpret a user request as the lowest-effort literal edit that satisfies
the words in isolation. Interpret it by the product outcome, affected boundary,
and adjacent invariants that must hold for the work to be complete.

## 4. Simplicity First

Minimum code or documentation that solves the problem. Nothing speculative.

- No features beyond what was asked.
- No abstractions for single-use code.
- No flexibility or configurability that was not requested.
- No broad folder trees before implementation needs them.
- Add helpers only when they name a real shared concept, preserve an invariant,
  or remove meaningful repetition.
- Avoid generic frameworks, registries, plugin layers, event buses, background
  schedulers, or broad configurability unless the verified requirement needs
  them.

Simple never means hardcoded, temporary, case-specific, or test-only. A simple
implementation must still validate inputs and outputs, handle errors, preserve
shared invariants, and cover affected paths with verification when available.

## 5. Surgical Changes

Touch only what you must. Clean up only your own changes.

When editing existing files:

- Do not improve adjacent code, comments, formatting, or wording unless it is
  part of the request.
- Do not refactor things that are not broken.
- Match existing style, even if you would do it differently.
- If you notice unrelated dead code or stale docs, mention it instead of
  deleting it.

When your changes create orphans:

- Remove imports, variables, functions, docs, or files that your changes made
  unused.
- Do not remove pre-existing dead code unless asked.

Every changed line should trace directly to the user request, the agreed
specification baseline, or an affected shared invariant.

## 6. Commands And Verification

Inspect `package.json` before running project commands. Do not invent scripts.

This repository has a root `package.json` with npm workspaces. Package-local
commands also work from `packages/client/`, `packages/mcp/`, and
`packages/provider-sui/`.

Current root commands:

- Build Gateway: `npm run build`
- Test Gateway: `npm test`

Current client package commands:

- Build: `cd packages/client && npm run build`
- Test: `cd packages/client && npm test`

Current MCP package commands:

- Build: `cd packages/mcp && npm run build`
- Test: `cd packages/mcp && npm test`

Current provider package commands:

- Build: `cd packages/provider-sui && npm run build`
- Test: `cd packages/provider-sui && npm test`

Current common firmware helper commands:

- Regenerate common Sui transaction facts fixtures:
  `firmware/tools/common/generate_sui_transaction_fixtures.mjs`
- Test common Sui transaction facts parser fixtures (host C++ compiler only;
  does not require ESP-IDF): `firmware/tools/common/test_sui_transaction_facts.sh`
- Test common policy v0 evaluator fixtures (host C++ compiler only; does not
  require ESP-IDF): `firmware/tools/common/test_policy_v0.sh`
- Test common policy v0 canonicalization fixtures (host C++ compiler only; does
  not require ESP-IDF): `firmware/tools/common/test_policy_canonical.sh`

Hardware-specific firmware commands live in the corresponding target
documentation under `firmware/src/<hardware-id>/`. Read that target's
README and SPEC before running target builds, target tests, flashing, or
hardware smoke checks.

Never claim a test, build, lint, pack, flash, or verification step passed unless
it was actually run and observed successfully.

When a hardware smoke check is run, record enough evidence for the next reader:
target hardware, commit, build or flash command, manual steps, observed result,
and any paths that were not checked. Put target-specific evidence in the target
documentation or in `.WORK/notes/`, and update implementation-status documents
when the verification level changes.

If a check cannot be run, state:

- the exact check that was skipped
- why it was unavailable, unsafe, or not applicable
- what risk remains

Check `git status --short` before the final response and classify unexpected
files.

## 7. Documentation Quality

When editing `AGENTS.md`, `README.md`, `specs/`, `docs/`, package READMEs, or
user-facing instructions, do a first-reader pass before calling the work
complete.

Read the changed document as if you have no prior conversation context. Verify
that it communicates:

- the purpose the document supports
- what is implemented, planned, unsupported, or intentionally out of scope
- the authority and boundary of every product, protocol, API, package, command,
  or workflow it mentions
- what the reader should do and what they must not infer

If the intended meaning depends on hidden chat context or vague shorthand,
rewrite it.

Repository-visible documentation, code comments, user-facing strings, package
metadata, protocols, tests, and release-facing copy should be written in
English. Ignored planning notes under `.WORK/` may use Korean when useful.

Use ordinary industry terms when available. Define unavoidable project terms at
first use and state what they do and do not mean.

## 8. Communication Rules

- Answer with verified facts and concise conclusions.
- Separate facts, assumptions, and recommendations.
- State uncertainty plainly when evidence is incomplete.
- Do not soften missing work, removed behavior, or incorrect prior claims.
- If work was not done, say it was not done.
- If a previous answer claimed completion incorrectly, say the claim was
  incorrect and state what is actually complete.
- Do not present planned behavior as implemented behavior.

## 9. Review Discipline

When asked for a review, prioritize defect discovery.

- Report findings first, ordered by severity.
- Cite file and line evidence for each finding.
- Check actual behavior instead of trusting comments or docs.
- Mark speculation clearly when evidence is incomplete.
- Review against the requested or planned behavior, not against a smaller
  behavior that happened to be implemented.
- Passing tests are useful evidence, not proof that every affected path is
  correct.
- If history shows prior behavior, classify the current work as restoration,
  replacement, or intentional removal before reviewing it as new functionality.

## 10. Implementation Integrity

- Reuse existing source-of-truth modules and established infrastructure when
  they own the boundary.
- Add new code only when no suitable source exists or the existing source is
  demonstrably insufficient.
- Do not duplicate logic, protocol metadata, parsers, policy checks, or SDK
  behavior without a clear reason.
- Do not hardcode values to bypass real validation, protocol checks, or product
  boundaries.
- Do not add temporary branches solely to satisfy one failing case.
- Do not manipulate tests, fixtures, generated files, package metadata,
  snapshots, or docs just to make checks pass.
- Test doubles, placeholders, and fixtures are allowed only when their scope is
  explicit and they are not presented as product functionality.
- Do not fake signatures, transactions, wallet state, key storage, policy
  enforcement, physical approval, chain support, transport support, or hardware
  readiness.
- Do not add production secrets or real key material.
- If technical debt remains, name it explicitly and explain the blocker.

## 11. Numeric, Signing, And Protocol Safety

Treat signable data and protocol-facing data as safety-critical.

- Keep raw amounts, gas values, object versions, nonces, chain ids, key ids,
  request ids, session ids, and protocol integers as strings or `BigInt` values
  when precision matters.
- Do not use floating point arithmetic for signable quantities or protocol
  integers.
- Keep display values presentation-only. Do not feed display strings back into
  signing or policy evaluation without an explicit conversion step.
- Do not infer decimals, asset identity, chain identity, ownership, signing
  readiness, or hardware readiness from symbols, UI labels, memory, or
  convenience defaults.
- If a protocol, SDK, firmware source, or hardware document does not define a
  term, quantity, status, or behavior clearly enough, mark it as unsupported,
  unavailable, or requiring verification.

## 12. Repository Notes

Current protocol session flow:

```text
get_status
  -> connect
    -> get_capabilities
    -> get_accounts
    -> policy_get
    -> get_approval_history
    -> sign_by_policy*
    -> sign_by_user*
  -> disconnect
```

`sign_by_policy*` means zero or more policy-authorized signing requests during
an active session.
`sign_by_user*` means zero or more device-confirmed signing requests during an
active session. Current adapters may project different subsets for their
audiences, but adapter projection is not the security boundary. Do not describe
either signing path as product-complete until tracked implementation status and
target hardware-smoke evidence for the current tree both say it is verified.

Current intended structure:

```text
package.json

specs/
  PROTOCOL.md

packages/
  client/
  mcp/
  provider-sui/

firmware/
  README.md
  src/
  tools/
    common/
    <hardware-id>/
  build/
```

Empty directories may not be tracked by Git until they contain files.

Project-specific rules:

- Keep planning notes, scratch files, investigation material, reference source
  checkouts, downloaded references, and vendor source snapshots under `.WORK/`.
- Use this `.WORK/` layout:
  - `.WORK/notes/` for planning notes, investigation summaries, and temporary
    project memos.
  - `.WORK/sources/` for upstream application, firmware, or example source
    checkouts used as references.
  - `.WORK/libraries/` for upstream library source checkouts used as
    references.
  - `.WORK/toolchains/` for SDK or toolchain source trees.
  - `.WORK/tools/` for installed local tools, tool caches, and downloaded
    tool archives.
  - `.WORK/artifacts/` for temporary logs, captures, generated fixtures, or
    one-off outputs that should not be committed.
- Do not commit files from `.WORK/`.
- Treat `.WORK/` sources as evidence context. They are not tracked project
  source unless a separate decision moves them into the repository.
- Do not use `.WORK/` as a source root for user-facing build instructions or
  GitHub workflows. CI and user builds must start from tracked repository files
  and explicit dependency setup steps.
- `.firmware-cache/` is an ignored local cache for pinned firmware build
  dependencies downloaded by tracked build scripts. Do not commit files from
  `.firmware-cache/`.
- Do not commit firmware build artifacts.
- `firmware/build/` is ignored and is for build output only.
- Firmware source is organized by hardware under
  `firmware/src/<hardware-id>/`.
- Treat Admin as a Gateway capability, not a separate product area.
- Avoid hardware-specific wording in common documents.
- Use concrete hardware names only in hardware-specific source, plans, or notes.

Avoid unless explicitly requested:

- separate Admin product directories
- additional package directories for internal concepts that are not actual npm
  packages
- separate chain-specific protocol documents
- broad speculative folder trees
- production secrets or real key material

## 13. Completion Criteria

Work is complete only when:

- the requested behavior is implemented, not merely planned or reported
- affected code, docs, interfaces, user flows, and product claims have been
  reviewed after the change
- the affected boundary still looks robust from product purpose, files, docs,
  protocol, tests, and user flows
- relevant checks, tests, builds, or manual verification have been run when
  available
- errors introduced by the change have been fixed
- remaining limitations or skipped checks are stated plainly
- non-trivial work is compared against the specification baseline, with every
  baseline requirement classified as implemented and verified, missing,
  weakened, or unverified
- final `git status --short` has been checked and unexpected files are
  classified or cleaned up
