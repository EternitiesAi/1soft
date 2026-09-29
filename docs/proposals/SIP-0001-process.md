# SIP-0001 — Protocol proposal and activation records

Status: Draft process proposal. Date: 28 September 2026.

A source merge, passing test, archived signature, or operator configuration edit is
not protocol activation. An improvement proposal records the intended rule and
its assumptions; a release records a particular implementation and evidence.

Every consensus-affecting change should identify the old and proposed protocol,
unchanged compatibility surfaces, authority that can approve the change, exact
activation boundary, state migration/commitment, bounded failure behavior, client
and state-sync effects, test vectors, and an actual-engine acceptance plan. Supply,
validator authority and governance policy must not be inferred from a software PR.

Suggested statuses are Draft, Specified, Implemented Candidate, Testnet Qualified,
and Activated. Each transition in status needs a dated source/evidence receipt.
An implementation may satisfy only part of a draft; list that scope instead of
promoting the whole proposal. Rejected/superseded proposals remain historical.

Activation needs a separately agreed network mechanism. No mechanism is selected
or installed here. Future implementations must reject unsupported versions before
changing state, preserve old history, and distinguish a node shutdown before
activation from rollback of already committed consensus history. After activation,
a locally installed older binary must not silently continue with obsolete rules.

Before changing the live protocol: freeze reference vectors; verify deterministic
execution across replicas and restart; test old-client refusal, version boundaries,
wallet evidence, state sync and any rollback/recovery procedure; run actual local
validators; then independent-host and external review gates. Engine execution is
not replaced by an author-produced signed-header fixture. Passing source tests
alone never changes a proposal to Activated.

Current protocols 1/2/3 and smt-v1 remain the supported development formats. These
process documents do not rename them, establish protocol 4, decide governance,
choose economics or approve public service/real funds.
