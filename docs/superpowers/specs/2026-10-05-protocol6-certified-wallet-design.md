# Protocol 6 certified treasury obligations

User authority: autonomous development toward completion and deployment readiness;
existing private-repository merge authority remains. No public/paid compute,
deployment, Actions, website/DNS, other projects, real funds, production keys or
force pushes. Scope is a new controller-only component; P1-P6 runtime, proofs and
historical receipts remain byte-identical.

The deliverable is a durable trusted-POSIX-host journal that retains a prepared
4008-byte P6 proof transaction, reserves its exact input/authority/request within
one canonical local journal, claims at most one delivery attempt before network
I/O, and records completion only from exact inclusion in authenticated state.
There is no proof-generation, signing, expiry release, transaction replacement,
custody, redemption, grant lifecycle or cross-device coordination claim.

## Choice and boundaries

Recommended: independently authenticate and replay the complete bounded P6 state
with its genesis-pinned worker, then atomically record exact executed bytes and
the observation. This costs proof verification for each new bounded state but
detects false semantic receipts even if a synthetic quorum signed them. A pure
quorum-trust resolver costs less but cannot independently reject invalid rule
execution. Reusing the old local treasury outbox would conflate local and P6
transaction domains and unsigned ledger observations; that route is rejected.

Grant lifecycle belongs in a new protocol, because P6 is explicitly static.
Do not add unsigned revoke or reinterpret P6 statements. A later profile needs
signed owner commands, chain/genesis/context/sequence binding, generation policy,
ordered concurrent payment semantics, replay/recovery and fresh proof fixtures.
Frozen P6 context does not include owner key/sequence/generation, so a design
must propagate that contract into a new context/proof identity before claiming
enrollment or rotation. Old notes cannot silently migrate to new generations.

## Interface

`CertifiedTreasuryJournal(path, *, expected_genesis: bytes, worker)` exposes
`retain(raw)->txid`, `claim(txid)->bytes`, `status(txid)->dict`,
`export(txid)->bytes`, `observe(witness, signed_header)->dict` and
`recorded_receipt(txid)->dict`. `deliver_once(txid, transport)->dict` claims before
calling `transport(raw)` once. An ordinary return or exception is an untrusted
delivery hint; neither records payment. Subsequent attempts are refused. No
automatic retry, re-sign, refreshed replacement or release exists.

The resolver verifies closed/bounded witness bytes, exact external genesis,
signed H+1 header, AppHash and complete P6 replay using the pinned worker. It
rejects older state and same-height conflicting AppHash. Same state with another
valid consensus round/header is allowed: height+AppHash identify the financial
checkpoint; a particular header's byte identity is not chain state identity.

Every observation contains all prior exact completion receipts and all retained
observations form monotonic state-prefix continuation. A higher state must keep
all checkpoint block bytes/results and payment receipts as a prefix. This is a
bounded complete-history check, not freshness or general light-client evolution.
Absence never releases an obligation, even after its payment window. Conflicting
value/request/authority nullifiers, outputs or stale grant/parent become typed
holds. Exact inclusion takes precedence over later changed authority. Statuses:
retained, attempted-held, observed-held, recorded-certified. Hold reason is
unknown, conflict or stale-authority; do not claim revocation in static P6.

## Persistence

SQLite FULL-sync WAL in an owner-only 0700 directory with regular owner-only0600
files and no symlinks. Exact schema: identity, observations and obligations.
Genesis bytes and component version are pinned. Reopen audits schema, bounds,
observation signatures/replay/continuation, raw obligations, derivable resource
keys, attempt state and exact saved certified inclusion. Evidence is retained
with original bytes. Local integrity is replay-based, not rollback/hostile-host
protection. A cloned/deleted database can lose attempt history; one canonical
trusted-host journal is mandatory.

BEGIN IMMEDIATE covers all retain/claim/observation updates. Each observe verifies
the new input before the write, audits its current checkpoint under the lock,
then records observation and every obligation classification together. SQL error
or process death gives complete old/new state. Concurrent connections serialize;
no application-global umask mutation. At most8 obligations,65 observations,
1MiB observation and bounded exported record sizes. Preserve original wires.

## Acceptance

Real pinned proofs plus real Ed25519 synthetic-quorum signatures test exact
completion, conflicting receipt fields, full replay, stale observations/forks,
unknown and post-expiry absence holds, same-height idempotence, one attempt and
lost-return recovery, concurrent retain/claim/observe, schema/wire/attempt/evidence
tamper, genesis mismatch, SQL rollback and process death before/after commit.
The actual CometBFT runner proves claim-before-submit, lost-return recovery from
the signed state, reopen/exact export, no second delivery, and a distinct valid
conflicting obligation staying held. Source/binary/fixture/process/log identities
and exact checks are independently gated. Simulated signatures are unit evidence;
actual validator receipt checks are separately registered.

## Completion and remaining release gates

This controller increment is complete when tests and real-engine source-bound
evidence pass, private PR is merged and one sanitized source/evidence ZIP is
verified. Product completion still requires owner lifecycle, merchant discovery/
redemption, safe proving/note custody, scalable state, independent operators,
specialist review, release/incident rehearsal and explicit public economics.
Do not describe a finite one-host development release as deployment-ready for
public value-bearing use. The authorized executor is this active Codex turn;
there is no unattended runner or scheduled continuation implied.
