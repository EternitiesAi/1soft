# 1soft privacy proof-stack benchmark

This isolated component runs one **actual Groth16 proof** for a frozen synthetic
one-input/two-output note relation. It exists to measure and attack a candidate
proof stack before any consensus, wallet, browser, RPC, deployment, custody, or
real-funds integration.

The candidate is gnark v0.16.3 with its declared gnark-crypto v0.21.0 dependency,
Groth16 over BN254 and Poseidon2. Every benchmark run generates fresh local setup
keys and retains only their hashes and sizes. The setup is not a ceremony or a
production parameter set. A passing run proves only that the exact synthetic
witness satisfied the exact experimental arithmetic relation under that run's
ephemeral keys.

## What the circuit binds

The fixed circuit proves one note opening and depth-four Merkle path, one derived
nullifier, two output commitments, 64-bit positive values, exact fee-inclusive
conservation, expiry ordering, and an authorization digest over the full ordered
public transaction binding. Public inputs are frozen and checked by the owned
Python receipt validator.

The proof cannot determine whether a chain accepts the supplied root, whether a
nullifier is globally fresh, whether outputs are inserted, or whether validators
apply the transition atomically. The transparent note lab remains the semantic
oracle for replay, receipts, state mutation and clone boundaries. Its SHA-256 and
Ed25519 bytes are deliberately not proof-compatible with this Poseidon2 profile.

## Verification

Populate the exact Go module cache once from the repository root:

```sh
cd tools/privacy-proof-benchmark/go
GOTOOLCHAIN=local go mod download
```

Then run the strict verifier from a clean Git commit, writing evidence outside
the checkout:

```sh
python tools/privacy-proof-benchmark/tools/verify.py \
  --report /path/outside/repository/privacy-proof-benchmark.json
```

The verifier checks the exact source manifest and Git identity, runs the Python
contract tests, and launches Go tests and the benchmark inside a new Linux user
and network namespace with module, sum-database, toolchain and VCS network
resolution disabled. Missing cached modules fail rather than silently going
online. See [VERIFICATION.md](VERIFICATION.md).

## Evidence boundary

A pass is evidence of a source-bound local benchmark and its listed rejection
cases. It is not production privacy, independent cryptographic review, consensus
integration, network anonymity, production custody, public-network readiness,
exchange readiness, or real-funds safety. See [STACK_SELECTION.md](STACK_SELECTION.md)
and the [design specification](../../docs/superpowers/specs/2026-10-04-privacy-proof-benchmark-design.md).
