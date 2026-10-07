# P8 wallet CLI AI review receipt

Two separate read-only AI reviewers inspected the protected wallet CLI, actual
caller adapter, process ownership and closed receipt checks. Root implemented
the change. Neither reviewer edited source or supplied a passing native receipt.
These are independent AI reviews within this task, not external specialist
certification or production approval.

## Ownership and authority reviewer

`/root/merchant_authority_review` reviewed the custody boundary, explicit trusted
genesis/credential/native inputs, command effects, durable holds, one-attempt
handling, private delivery, publication claims and actual receipt semantics.
The reviewer accepted fresh run03 at source
`051f8397a5bc57ccc21a428b6bd57a8c14f0c141`: 13 caller checks, 22 underlying
wallet checks, 57 canonical CLI invocations/responses and 16 expected refusals.
It found no material defect in the selected receipt or raw CLI stream. Its final
followup also accepted the completed separate replay: four proofs, three signed
AS-OF states, 39 reaped native calls, no timeout and no freshness claim.

## Native and process reviewer

`/root/merchant_native_review` reviewed the unchanged native wallet journey,
receipt binding, private-output exclusions, cleanup ownership, strict invocation
identity and native/process evidence. It accepted fresh run03 at the same source,
including two actual encrypted pre-proof holds with no wire and zero attempts,
exact lost-response reconciliation, recipient delivery/import and genuine
competing-spend conflict. Its final followup verified the separate replay and
confirmed 39/39 native calls reaped, no timeouts and explicit AS-OF scope.

## Resolved issues and preserved negative evidence

Root cancelled run01 before qualification after finding that cleanup compared
mutable scheduler state as part of process identity. Cleanup now compares the
immutable creation ticks of the same PID. Two actual disposable process tests
cover a scheduler-state transition and a child in a separate process session.
Nine processes in the captured owned ancestry, including its root, stopped. The
original partial report defaults to failed and is retained as cancelled evidence.

Run02 passed all 22 inherited actual wallet checks but failed the outer caller
sequence because the frozen expected list omitted Carol's unchanged inventory
call after private import. The exact required list now includes all 57 commands;
no underlying wallet check or intended refusal was removed. Root committed the
correction before a wholly fresh run03. Both reviewers accepted that correction
and the new qualification; run02 remains a failed outer gate.

The checker additionally requires valid positive CLI/native PID and creation
identities. Twenty-one receipt mutations refused, including recomputed raw-stream
and invocation hashes. Passing consistency checks supplement actual execution;
they do not create native execution or upgrade old failed reports.

## Accepted scope

One trusted Linux/WSL host, four local validators, finite synthetic funds and
test credentials. The CLI performs local protected wallet operations; an explicit
external caller submits the test transaction. Static quorum observations remain
AS-OF. Public network, freshness, production key management/privacy, independent
hosts/signers, rollback resistance, economics and public launch are unassessed.
