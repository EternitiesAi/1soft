# Protocol 5 wallet continuity

The finite development wallet now pays a selected recipient using only that
recipient's public owner key, preserves the exact proved transaction through a
lost approval return, and hands off one selected output through a private capsule.
Two distinct synthetic wallets have exercised that flow with actual Halo2 proofs
on four local CometBFT validators. This is one trusted-host development qualification.

## What the wallet preserves

Preparation records a review without signing, proving or paying. Approval durably
records the exact TransactionV1, input hold and private output openings before
returning bytes. If that return is lost, recovery retrieves the stored transaction
without another proof. A decline, missing receipt, expiry or a conflicting winner
retains the unresolved obligation; none silently releases the hold.

A separate delivery journal commits one attempt before network I/O. It has no
automatic retry or second-journal fallback. Endpoint admission is an observation.
Collection and wallet reconciliation remain separate, and execution classification
requires the exact bounded state authenticated by its signed H+1 header.

The payer exports a private NoteCapsuleV1 for one selected output. Its recipient
verifies/imports the exact capsule against authenticated chain state, then spends
with another actual proof. This is an explicit private handoff and a scan for known
commitments; it is not encrypted on-chain note discovery or anonymous transport.

The controller-only Rust client adds opcodes 3 (derive owner key), 4 (spend to
recipient keys) and 5 (derive note nullifier). Existing opcodes and prover/witness/
transaction formats remain unchanged. Python never reimplements the Poseidon
commitment, spend key, nullifier or proof relation. Client/prover binaries remain
outside validator homes and traffic. The Protocol 5 circuit, profile, KAT,
verifier worker, deployment and consensus/state-sync semantics remain unchanged.

## Local use and evidence

Use `python scripts/protocol5_wallet.py --help` for explicit local commands. Secret
inputs enter through stdin or private files, with exclusive no-follow 0600 outputs.
Private journals require a trusted local POSIX directory, SQLite WAL and FULL
synchronization. The CLI exposes review, approve, recover, capsule export/import,
signed state sync, and one-attempt delivery/collection/reconciliation operations.
Only explicit loopback RPC endpoints are accepted.

The [component manifest](../tools/protocol5-wallet/COMPONENT_MANIFEST.json) pins the
clean implementation, binaries, profile, settings, report/checker and artifact
identities. The [dependency receipt](../tools/protocol5-wallet/DEPENDENCY_RECEIPT.json)
records separate locked offline worker/development graphs; no new Python direct
dependency was added. Thirteen wallet scenario groups, eighteen consensus regression
groups and eight state-sync groups must pass their strict external checkers. Raw
private journals, capsules, openings and host paths are excluded from registration.
Historical Protocol 5 receipts remain historical; they do not claim these later
controller opcodes or wallet behaviors.

## Limits and next step

Synthetic keys and a single trusted host are the boundary. There is no production
custody, hostile-host rollback protection, copied-journal/cross-device coordination,
scalable note storage, anonymity, metadata privacy, safe capsule transport,
independent cryptographic/security audit, public deployment, real users/funds or
economic-value claim. A qualified automated receipt cannot certify those properties.

The next shared-authority protocol must atomically bind a private mission allowance
to value-note conservation, current enrolled/revoked authority, authenticated
validator state and these durable obligations. This wallet supplies the continuity
prerequisite; it does not itself implement the shared-authority relation. Read the
[product direction](PRIVATE_ECONOMIC_AUTHORITY_DIRECTION.md) and
[accepted wallet design](superpowers/specs/2026-10-04-protocol5-wallet-continuity-design.md).
