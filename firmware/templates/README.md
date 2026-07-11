# Firmware Target Templates

These templates define the minimum tracked documentation and verification shape
for adding a new Firmware hardware target.

They are not planning notes. Copy them into the new target directory and replace
every placeholder before implementing product behavior.

Required files for a new target:

- `firmware/src/<hardware-id>/README.md`, based on
  `target-README.template.md`.
- `firmware/src/<hardware-id>/SPEC.md`, based on
  `target-SPEC.template.md`.
- A target test checklist based on `target-required-tests.template.md`, either
  as target documentation or as concrete scripts under
  `firmware/tools/<hardware-id>/`.

The templates exist to prevent target fragmentation:

- shared protocol methods, request schemas, response schemas, status fields,
  public error codes, and method result schemas stay global;
- target-independent product state, transition order, error precedence, and
  sensitive scratch cleanup use common modules once the shared contract is
  proven;
- target directories own only target composition and real target adapters:
  display/input/power behavior, board runtime integration, transport adapter,
  storage adapter, identity adapter, and signing-material adapter.

Do not use these templates to add target-specific product APIs, debug state
setters, host-triggered setup, host-triggered reset, proof-clear methods,
signer selectors, or internal-state inspection surfaces.
