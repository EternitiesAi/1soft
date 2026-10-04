# Verification contract

The component has two independently required backend verifiers. Neither accepts a
supplied success receipt as evidence that its proof backend ran.

## Shared source gates

Both verifiers require:

- a clean, non-shallow Git worktree at a full commit and tree identity;
- an exact `SOURCE_MANIFEST.json` containing every component source, test,
  dependency, lock and documentation file exactly once with byte length and
  SHA-256;
- no symlinks, extra files, stale Python bytecode or backend build outputs;
- the exact closed Python receipt-contract test inventory;
- new report and raw-log paths outside the repository;
- independently observed Git and circuit-source identities before execution and
  an unchanged source identity afterward.

## Groth16 execution gate

The Groth16 verifier runs `go test`, a clean build and the owned benchmark under
`unshare -Urn` with `GOPROXY=off`, `GOSUMDB=off`,
`GOTOOLCHAIN=local`, `GOVCS=*:off` and `-mod=readonly`. It requires stable
Linux Go 1.25.7 or newer and the exact pre-cached module graph.

Its closed receipt binds gnark v0.16.3, gnark-crypto v0.21.0, BN254, Groth16,
Poseidon2, the circuit source, constraint count, ephemeral setup keys, proof,
public witness, measurements and exact cases. Serialized setup keys, proof and
private witness bytes are not retained.

## Halo2 execution gate

The Halo2 verifier independently runs Rust unit tests, a release build and the
owned benchmark under a fresh `unshare -Urn` boundary with
`CARGO_NET_OFFLINE=true`, `cargo --locked --offline`, Rust toolchain
1.97.1 and a new external `CARGO_TARGET_DIR`. Stable Linux Rust 1.88 or newer
is required. A missing cached crate or changed lockfile fails; no registry or
toolchain download is allowed inside verification.

Its closed receipt binds:

- `halo2_proofs` 0.4.0, `halo2_gadgets` 0.6.0,
  `halo2_poseidon` 0.2.0 and `pasta_curves` 0.6.0;
- Pallas base-field arithmetic, Vesta IPA commitments, the Blake2b transcript and
  Poseidon P128Pow5T3;
- the independent Halo2 circuit-source digest, power `k`, domain rows,
  estimated proof bytes and exact ordered public inputs;
- deterministic public parameter hash and size;
- a version-bound nonportable pinned-verifying-key debug binding;
- explicit absence of a supported proving-key serialization/size assessment;
- actual proof and canonical public-instance hashes and sizes;
- positive parameter, key-generation, proving and verification measurements;
- one accepted proof and nine independently rejected mutations;
- exact false production claims and exact unassessed boundaries.

The network namespace is an offline boundary for backend execution, not a general
filesystem sandbox. The verifier runs the owned local source with the invoking
user's filesystem permissions.

## Exact adversarial inventory

| Case | Required result |
| --- | --- |
| valid proof | accept |
| mutated proof | reject |
| changed public input | reject |
| wrong verifying key | reject |
| invalid membership | reject |
| invalid nullifier | reject |
| invalid output commitment | reject |
| invalid fee conservation | reject |
| out-of-range value | reject |
| changed authorization digest | reject |

The Halo2 constraint-specific mutations first fail the real MockProver and then
reach actual proof creation or verification; a returned proof must fail the real
verifier. Wrong-spend-secret, duplicate-output and output-to-input composability
are additional circuit unit tests.

Both receipt validators refuse duplicate JSON keys, nonfinite/floating numbers,
integer substitutes for booleans, extra or missing fields, stale source
identities, case omissions or duplicates, zero measurements and any promoted
production claim. A successful local proof remains experimental engineering
evidence rather than a cryptographic audit or deployment qualification.
