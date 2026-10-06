# Reproduce the P8 native component

The executed source and tree are recorded in source-freeze-02.json. Registration
adds documentation/evidence only; every runtime file in the selected receipt
must still match. Use a clean checkout with the required Cargo.lock dependencies
already available. The recorded environment was Linux x86_64 in local Ubuntu WSL,
rustc1.97.1(8bab26f4f), cargo1.97.1 and Python3.14.4. No network service or validator
is needed. The receipt contains public synthetic bootstrap/state/wires; it is
not key provisioning or a real wallet.

Build the crate's tests/prover/fixture offline and locked with two compile jobs.
Build recipient-verifier separately with --no-default-features and a separate
target directory. Record the exact binaries' SHA256 and lengths. Use the commands
in tools/recipient-transfer/README.md and scripts/run_protocol8_recipient.py --help.
The run refuses dirty source and existing outputs. It takes explicit paths and
digest pins for all three binaries, then emits public evidence and sanitized
operation/exit/byte-count metadata. Private request stdin is not retained.

For public replay only:

```sh
python scripts/check_protocol8_recipient_report.py evidence/protocol8-recipient/20261006/recipient-qualified-02.json --verifier /absolute/recipient-verifier --verifier-sha256 EXTERNALLY_TRUSTED_VERIFIER_DIGEST --genesis-sha256 EXTERNALLY_TRUSTED_GENESIS_DIGEST
```

The original verifier digest and synthetic genesis digest are in the selected
receipt. Authenticate those pins through a source you already trust; copying
untrusted report values creates no trust. A rebuilt binary may have another
digest and must be independently accepted; never waive native profile identity
checks. Public replay recomputes four actual proofs and two accepted receipts,
then verifies refusal of a valid competing spend. The finite tree has16 slots;
this is not a public-network, production-custody or scaling benchmark.
