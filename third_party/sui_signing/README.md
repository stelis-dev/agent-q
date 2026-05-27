# Sui Signing Dependency

This directory vendors the minimal source needed by the current firmware
signing self-test.

Source:
- Version checked locally: v0.3.4
- License: MIT, see `LICENSE`

Only the Ed25519 signing path and the cryptographic dependency it requires are
copied here.
Do not treat this directory as a complete Sui transaction builder, wallet,
policy engine, or network client.
