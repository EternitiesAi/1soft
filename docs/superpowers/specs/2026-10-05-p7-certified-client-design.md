# P7 certified owner/payment client

Scope: one exact local FULL-sync WAL journal retaining prepared P7 owner commands
and payments, one committed attempt before bounded loopback transport, and exact
completion from a independently replayed quorum certificate. No signer/prover,
production custody, freshness, retry, migration, public deployment, paid compute
or other projects. Preserve every frozen protocol/kernel/service and old receipt.

The immutable full genesis and profile/worker/KAT/bootstrap identities scope the
journal. Canonical raw wire is authoritative; checked resource projections support
live uniqueness for shared context, parent/grant authority, input/request and
owner sequence lane. Exactly one competing command/parent payment can be retained
per protected local resource. Separate connections serialize in BEGIN IMMEDIATE.
Known conflict/revoke/rotation/stale context or elapsed window refuses even the
first claim. Unknown acknowledgement or absence keeps the exact obligation held.
Completion requires exact typed raw receipt inclusion, not equivalent intent.

AS-OF stateH is authenticated by a COMMIT at blockH+1. That block already exists;
the next newly submitted transaction cannot execute before H+2, even though its
application state is not in this observation. Current-state CAS remains AS-OF,
and an unseen block can stale it. Earliest known execution is certificate height
plus1; existing longer payment windows are valid when they include that height.
An owner command in the already committed range stays held/unknown pending a
full matching state receipt. Never release or retry from absence.

Add an explicit optional local admission companion, preserving the original P7
service/kernel byte-for-byte. It checks owner signature/current context CAS with
declared height between appnext and appnext+7 (within64), without generating
synthetic blocks or committing any successor. The frozen proposal/finalization
kernel remains exact-height. Future admitted commands wait for their declared
height and become invalid if context changes. This eight-height limit is local
mempool/preparation policy, not a new consensus/proof rule. Payments retain their
existing signed validity interval and current-state/proof checks.

Require real proof/Ed25519 tests for both wire types, live resource/sequence races,
trusted-host journal crash/reopen/audit, certificate continuation and typed holds,
claim-before-I/O and refused redirects/proxies/retries. Then an actual owned local
four-validator caller run must demonstrate future owner admission, exact-height
execution, acknowledgement loss, certified recovery and an unclaimed stale
obligation refused before its first attempt. No authored certificate may qualify
as real validator evidence.
