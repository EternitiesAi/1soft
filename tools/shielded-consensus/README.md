# Protocol 5 shielded consensus

This component is the fresh-genesis, finite Protocol 5 development chain. It
places actual Halo2 proof verification inside the ABCI admission path while the
application owns deterministic ordering, a depth-four append-only note tree,
bounded authenticated root history, global nullifier and output uniqueness,
fees, receipts, atomic persistence, restart audit, and marker-only state sync.
It does not modify Protocol 4 and has no transparent-native bridge.

The qualified implementation is commit
`6a8f33c9e5e6fa53ff2cb13ae66df9c81d7d79ff`, tree
`f98000a92e780c8cc54338345db18696a55cd8d0`. The registration files were added
after that run; [COMPONENT_MANIFEST.json](COMPONENT_MANIFEST.json) records the
executed source tree, every pinned artifact identity, and the final evidence
hashes. The complete normative contract is the
[accepted design](../../docs/superpowers/specs/2026-10-04-shielded-consensus-admission-design.md),
and the operator-facing summary is [Protocol 5 shielded
consensus](../../docs/PROTOCOL5_SHIELDED_CONSENSUS.md).

## Cryptographic profile

The standalone [Rust crate](halo2/Cargo.toml) freezes
`1soft/shielded-consensus/halo2-pasta/v1`: Zcash Halo2 0.4.0, IPA over Pasta,
Blake2b transcript, Poseidon P128Pow5T3, K=13, fourteen public fields, a
four-level tree, and an exact 3,136-byte proof. The profile identity is
`272f8ea5ea7e04fa24b27c5125650150760b618229f2f3fbe0b7cc95bbca3eef`.
The qualified executable deployment identity is
`76129871a4659caf919ccdb32c545b0330b4ba1018cf6b1ec85ac61582eb3cac`.

The tracked [profile descriptor](profile/profile-descriptor-v1.bin),
[KAT](profile/kat-v1.bin), [public schema](profile/public-schema-v1.json),
[profile manifest](profile/profile-manifest-v1.json),
[toolchain manifest](profile/toolchain-manifest-v1.json),
[sandbox policy](profile/sandbox-policy-v1.json), and
[golden vectors](test-vectors/crypto-v1.json) are identity-bearing inputs.
Halo2 0.4.0 does not provide a portable verifying-key serialization, so the
verifying-key binding is pinned to this implementation and toolchain profile;
this is not a cross-platform reproducible-build claim.

The validator runs only `shielded-verifier-worker`. It takes no arguments,
performs its profile/KAT startup checks, closes every file descriptor except framed stdin/stdout,
sets `no_new_privs`, installs the recorded x86_64 Linux seccomp deny policy,
checks that post-install file and socket probes fail, then accepts only the four
framed verifier operations. The worker is single-threaded and contains no
witness or proving operation.

`shielded-development-client` and `shielded-development-prover` are separate
controller-only binaries. The client derives note commitments, authentication
paths, public fields, and the exact 480-byte WitnessV1. The prover reads one
exact ProverRequestV1 from standard input and emits only TransactionV1. Secrets
remain on controller standard input; neither binary belongs in a validator
home, validator command line, ABCI request, state database, snapshot, receipt,
or log.

## Build and test separation

Use the pinned Rust 1.97.1 toolchain, an external target directory, the locked
crate, and offline dependency resolution. Worker and development-prover
features must be built and tested separately; do not use `--all-features`.

```sh
export P5_BUILD_ROOT="${P5_BUILD_ROOT:?set to a fresh directory outside the repository}"
export CARGO_TARGET_DIR="$P5_BUILD_ROOT/target"
export CARGO_NET_OFFLINE=true

cargo +1.97.1 test --locked --offline --no-default-features \
  --features worker \
  --manifest-path tools/shielded-consensus/halo2/Cargo.toml \
  -- --test-threads=1

cargo +1.97.1 test --locked --offline --no-default-features \
  --features dev-prover \
  --manifest-path tools/shielded-consensus/halo2/Cargo.toml \
  -- --test-threads=1

cargo +1.97.1 build --release --locked --offline --no-default-features \
  --features worker \
  --manifest-path tools/shielded-consensus/halo2/Cargo.toml \
  --bin shielded-verifier-worker --bin shielded-sandbox-probe

cargo +1.97.1 build --release --locked --offline --no-default-features \
  --features dev-prover \
  --manifest-path tools/shielded-consensus/halo2/Cargo.toml \
  --bin shielded-development-client \
  --bin shielded-development-prover \
  --bin shielded-profile-builder
```

The [dependency receipt](DEPENDENCY_RECEIPT.json) is generated from two separate
`cargo metadata --locked --offline --no-default-features` resolutions. It
records the worker and `dev-prover` graphs independently and their deterministic
union. A dependency list is not a vulnerability assessment or legal clearance.

To regenerate identity artifacts, first finish every Rust source and Cargo
change, build the development profile builder, and direct it to a fresh external
directory. Run it twice into two fresh directories and require byte identity
before replacing tracked files. Any descriptor, KAT, Cargo lock, circuit,
toolchain, worker, or sandbox-policy change requires a new profile or deployment
identity and a new genesis.

```sh
"$CARGO_TARGET_DIR/release/shielded-profile-builder" "$P5_BUILD_ROOT/profile-a"
"$CARGO_TARGET_DIR/release/shielded-profile-builder" "$P5_BUILD_ROOT/profile-b"
cmp -r "$P5_BUILD_ROOT/profile-a" "$P5_BUILD_ROOT/profile-b"
```

## Genesis and execution boundary

[build_protocol5_inputs.py](../../scripts/build_protocol5_inputs.py) combines
the measured worker, descriptor, toolchain, policy, and closed qualification
settings into DeploymentBindingV1 and a canonical empty-commitment genesis
template. A controller derives `genesis_field` from the canonical projection
with both `genesis_field` and `initial_commitments` absent, then invokes the Rust
client to derive spendable initial commitments. The final canonical genesis
SHA-256 binds the inserted commitment list.

The application starts one exact worker per validator and rejects path
replacement, unsafe ownership or mode, hash drift, profile drift, KAT failure,
or sandbox failure. CheckTx, proposal preparation, proposal validation,
FinalizeBlock, restart replay, and state-sync replay share the same deterministic
evaluator. Verifier death, timeout, malformed framing, or internal divergence
produces no consensus result and quarantines the application until a clean
restart.

The chain is intentionally finite: four fixed equal-power validators, height at
most 512, a sixteen-leaf tree, exactly two outputs per accepted transaction, at
most eight transactions per block, and bounded retained history and snapshots.
See the guide for all hard ceilings, queries, recovery behavior, and launch
inputs.

## Qualification evidence

The final one-host loopback runs used CometBFT 0.38.25 and synthetic DEV notes.
The consensus receipt `consensus-05.json` and state-sync receipt
`state-sync-03.json` both bind the qualified commit/tree, profile, deployment,
binaries, generated genesis, process identities, passed scenario identifiers,
and retained artifact manifests. They remain
`completed-awaiting-external-validation`; the separate strict checker receipts
record `qualified: true`. Raw reports, process logs, databases, and secrets stay
outside the repository. Their basenames, sizes, SHA-256 values, and check rosters
are recorded in [COMPONENT_MANIFEST.json](COMPONENT_MANIFEST.json).

The consensus gate admitted actual proofs, exercised conflicting randomized
proofs, historical-root sequencing, uniqueness, validity bounds, worker
kill/stall recovery, pre/post-commit crashes, application/engine restart,
three-of-four continuation, sandbox probes, and a secret-leakage scan. The
state-sync gate used four source validators and a never-started target, replayed
to a light-client-authenticated AppHash, preserved a marker-only checkpoint,
observed final-Apply process exit 96 and CometBFT re-offer, exercised hostile
offers/chunks and rollback refusal, continued, and restarted the same store.

This evidence supports one fresh finite development chain on one host. It does
not establish production security or privacy, anonymity or network-metadata
privacy, independent security or cryptographic review, production custody,
public-network or exchange readiness, real-funds safety, scalable note storage,
multi-host Byzantine behavior, wallet scanning/recovery, or economic value.
Every such claim remains false.

## Later Protocol 5 wallet continuity

The [finite trusted-host wallet](../../docs/PROTOCOL5_WALLET_CONTINUITY.md) adds recipient-key payments, exact
lost-return recovery, selected-output capsules, authenticated H+1 reconciliation
and one-attempt delivery. These later controller-only additions preserve the
existing circuit/profile/KAT/worker and historical qualification identities.
They do not establish production custody, privacy, public deployment or real-funds safety.
