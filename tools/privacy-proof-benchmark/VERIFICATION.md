# Verification contract

The component verifier owns the process boundary. It does not accept a supplied
success receipt as evidence that the backend ran.

## Source and execution gates

- The checkout must be a clean, non-shallow Git worktree at a full commit and
  tree identity.
- `SOURCE_MANIFEST.json` must list every owned source, test, dependency and
  documentation file exactly once with its SHA-256 digest. Symlinks, missing,
  extra and changed files fail.
- Python receipt-contract tests must pass without bytecode output.
- `go test` and the benchmark run under `unshare -Urn` with `GOPROXY=off`,
  `GOSUMDB=off`, `GOTOOLCHAIN=local`, `GOVCS=*:off` and `-mod=readonly`.
- The benchmark report destination must be newly created outside the repository.
  Existing paths and repository descendants fail.
- Git commit/tree and circuit-source digest are independently observed by the
  verifier and must match the Go receipt.

The network namespace is the offline boundary for Go execution. It is not a
general operating-system sandbox: the benchmark still runs local compiled code
with the invoking user's filesystem permissions.

## Closed backend receipt

The receipt uses exact fields and types. It binds:

- gnark v0.16.3, gnark-crypto v0.21.0, BN254, Groth16, Poseidon2 and Apache-2.0;
- circuit profile, source digest, constraint count, fixed depth/input/output/
  value widths and ordered public inputs;
- Git commit and tree;
- ephemeral setup kind plus proving/verifying-key hashes and byte sizes;
- proof and public-witness hashes and byte sizes;
- positive compile, setup, prove and verify nanosecond measurements;
- one accepted valid proof and nine independently rejected mutations;
- exact false production claims and exact unassessed boundaries.

The record contains no witness, secret, private key, serialized setup key or
serialized proof. Hashes are evidence bindings, not recovery material.

## Adversarial cases

The exact case inventory is:

| Case | Required result |
| --- | --- |
| valid proof | accept |
| mutated proof | reject |
| changed public input | reject |
| wrong verifying key | reject |
| invalid membership | reject before a valid proof is produced |
| invalid nullifier | reject before a valid proof is produced |
| invalid output commitment | reject before a valid proof is produced |
| invalid fee conservation | reject before a valid proof is produced |
| out-of-range value | reject before a valid proof is produced |
| changed authorization digest | reject before a valid proof is produced |

The receipt validator refuses duplicate JSON keys, nonfinite/floating values,
integer substitutes for booleans, extra or missing fields, stale identities,
case omissions/duplicates, zero measurements and any promoted production claim.
