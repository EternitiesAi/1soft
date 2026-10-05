# Read-only AI reviews

Two separate read-only AI reviewers inspected the combined relation and the local
execution/recovery boundary. This is not an independent specialist security or
cryptographic audit.

The circuit review checked shared payment/recipient/agent cells, conservation,
restricted change, Merkle membership/nullification, successor policy and profile
separation. An initial expiry concern was withdrawn: execution height is below
transaction until, which is bounded by grant expiry, even if a note lives longer.
An explicit native/MockProver case covers that boundary. The final review found
no blocking P1/P2 circuit defect within the stated local scope.

The ledger review led to additional concurrent-claim/connection tests, a distinct
proved duplicate-request fixture, and actual process-exit tests before and after
commit. An initialization lock failure masked its cause and leaked a connection;
the regression failed before repair and passed after conditional rollback and
unconditional close. Tests also exposed a global umask race, repaired through
explicit private-file creation without changing process-wide permissions.

The provenance review confirmed the final qualifier captures clean source before
execution and verifies it afterward, binds the result's verifier identity to its
execution log, passes a fixed expected digest to all verification callers, and
rechecks the bounded regular binary around execution. The final review found no
remaining blocking P1/P2 issue in these changes.

Receipts remain local evidence. Rewriting a report together with all logs and
hashes can fabricate a receipt; no signed, immutable, independently attested or
publisher-grade provenance is claimed. Unknown claimed obligations cannot be
cleared from absence, timeout, expiry, rejection or revocation. This availability
limit is deliberate pending a future certified resolution contract.
