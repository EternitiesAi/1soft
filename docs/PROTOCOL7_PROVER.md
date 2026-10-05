# P7 bounded developer proof preparation

This increment connects arbitrary canonical developer Assignment/Witness inputs
to the selected P7 relation and certified local journal. It does not change P7
consensus, the profile JSON, parameters, verifier key, or P1-P6 formats. The
consensus bridge remains verifier-only.

## Interface and authority

Build the separate binary with the tracked lockfile and existing dependencies:

    cargo build --offline --locked --release \
      --manifest-path tools/owner-treasury-lab/halo2/Cargo.toml \
      --bin owner-payment-prover -j 2

On the trusted POSIX host, instantiate protocol7_prover.Prover with an
explicit measured binary SHA-256, external canonical genesis, and the journal's
pinned Worker. Call journal.prepare(prover, public, witness). The public input
order is the existing profile's 30 fields. Private witness order is:

1. parent cap, spent, version, blind, next blind;
2. grant cap, spent, version, blind, next blind, expiry;
3. agent secret, recipient, payment value, payment blind;
4. input position, value, expiry, note secret, blind;
5. four Merkle path fields;
6. change value, key, expiry, note secret, blind;
7. payment-note expiry and note secret.

Each input is a lowercase canonical 32-byte little-endian field hex string.
Integer slots must fit u64; position must be below16. Extra/missing fields,
noncanonical field elements, unsupported versions and out-of-range integers
are refused. The Rust request is exactly2088 bytes: magic, profile/parameter/VK/
bootstrap identities,30 public fields and31 private fields. No caller seed or
request normalization is accepted. The prover validates the relation, checks
network-domain binding, uses a fresh32-byte OS-random seed, checks the frozen
profile identities, proves and locally verifies, then emits exactly4168 bytes.

The standalone binary establishes relation validity, not current permission.
The journal's prepare method audits the canonical retained history under one
SQLite write transaction. It checks the AS-OF owner/grant/context, valid anchor,
execution window, spent resources and live reservations before sending openings
to the child. It independently verifies the exact returned statement/proof and
runs the existing full preflight before inserting the obligation. The committed
return is its transaction ID. It does not claim a delivery attempt or submit.
Subsequent delivery remains the existing one-attempt path; an unknown outcome
keeps the original obligation.

The write lock deliberately spans proving and retention. A competing connection
waits or fails with the existing SQLite timeout, and cannot reserve the same
resources concurrently. This is local serialization, not cross-device fencing
or a freshness guarantee. No encrypted note construction, note discovery,
merchant redemption or key-recovery mechanism is introduced by this API.

## Process and privacy boundary

The parent opens a regular, owner-controlled, non-symlink executable and checks
its SHA-256 before executing that measured inode. The child receives no inherited
credential environment. It has bounded CPU, address space, file output, open
files and wall time; core dumps are disabled. A failed or timed-out child is
killed and reaped, and the journal write transaction rolls back.

Private openings travel over stdin and ordinary process memory. They are never
written to the result report or retained journal, hashed into a public guessing
target, printed by the prover, or sent to validators. The process is not a
hostile-host sandbox, secure enclave, memory-erasure guarantee or production
custody solution. The binary's failure diagnostic is static. The wrapper refuses
nonzero exits, any diagnostics, short/trailing output, another valid statement,
or an invalid proof.

The receipt retains only the publicly reconstructible request-prefix digest,
public identity fields, returned wire, process identity/exit and actual execution
evidence. It does not claim an independent attestation of private input bytes.

## Qualification

[Prover tests](../tests/test_protocol7_prover.py) cover actual proving, exact
reopening, stale/wrong state before proving, corrupt witnesses, measured-binary
restrictions, real malformed/failing/echoing/timed-out child processes, insert
rollback and concurrent journal connections. Explicit fault doubles cover
database failure and serialized reservation; they do not establish actual proof
generation.

The Rust prover_request test mutates every public/private slot, identity
headers, lengths, fields and integer range, then verifies two independently
randomized actual binary proofs against the frozen profile.

[Actual engine runner](../scripts/run_protocol7_prover.py) is an additive gate.
It uses a fresh four-validator bootstrap and a separately labeled synthetic
opening generator. The generated payment statement differs from all twelve
existing fixtures. The gate prepares and retains the proof, submits once,
deliberately discards the returned acknowledgement, authenticates exact execution
with the signed next header, reopens, refuses redelivery and forged certificates,
and restarts a validator. Private requests are not exported.

[Receipt checker](../tools/release/check_protocol7_prover.py) independently checks
closed claims, clean executed Git source/dependencies, measured binaries and
process lifecycle, exact artifact inventory/hashes, public request bindings,
real proof and certificate replay. Candidate runs cannot qualify. The old P7
lifecycle/client gate and historical receipts remain unchanged.

The [registered clean-source receipt](../evidence/protocol7-prover/20261005/prover-qualified-01.json)
passed all16 checks at execution source
`ad4d011c93c58da19ed83cedbe01051ce46f59d7`; the independent replay checker
and all4 adversarial receipt tests passed. The [AI review and validation scope](../evidence/protocol7-prover/20261005/AI_REVIEW.md)
records the exact tests, resolved failures and remaining limits. Encrypted
authentic restricted CHANGE import/spend is now [qualified on one host](PROTOCOL7_VAULT.md);
recipient discovery, merchant redemption and production custody remain [readiness gates](DEPLOYMENT_READINESS.md).
No public launch, real funds, independent-operator or production privacy claim
follows.
