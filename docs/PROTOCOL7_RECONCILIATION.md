# Read-only preparation reconciliation

preparation_status(journal, commitment) and the protected-stdin inspect-prepared
command inspect one exact encrypted preparation against one audited journal
snapshot. They do not prepare, prove, submit, release holds, clear stages or retry.
The external key is required and never returned. Missing/tampered ciphertext,
wrong pins, missing input or ambiguous matching journal wires refuse.

| Status | Meaning at the reported snapshot |
|---|---|
| staged-without-retained-wire | The authenticated encrypted request exists; this journal snapshot has no exact retained public request/wire |
| retained-held | The exact wire is retained and its local delivery attempt count is zero |
| attempted-held | The exact wire has one claimed delivery attempt and remains an obligation |
| recorded-certified | Exact execution is authenticated by the journal's retained quorum certificate |

Every closed public result contains the input commitment, request/source IDs,
vault revision, authenticated AS-OF height/AppHash, and exact wire ID/digest,
attempts, hold reason and completed height when a matching row exists. The latter
fields are null for staged-without-retained-wire. No proof/wire, private amount,
opening, authority or decrypted payload is returned. A certified height is a
snapshot, not a promise of network latestness or spendable balance.

latest_state_guaranteed, in_flight_state_known, retry_authorized and
automatic_retry are always false. Snapshot absence cannot establish that a
prover/validator/other process is absent. It never authorizes regeneration or
resubmission. Keep the original request/obligation and reconcile it explicitly.
The status can become stale immediately after return.

The method authenticates the vault while holding its lock, then reads the journal
under one atomic audit. It uses that same snapshot for wire selection, attempt
count, resolution and AS-OF identity; it never nests another journal transaction.
The vault-to-journal lock order matches ordinary preparation. It writes neither
vault payload nor journal rows. CLI failure diagnostics remain fixed and private.

The additive run_protocol7_reconciliation.py gate includes the complete retained
authority trace plus actual status-caller observations before delivery, after a
discarded accepted return, and after exact second/third certificates. A separately
owned temporary vault exercises a labeled fault after actual encrypted staging
but before journal preparation, with zero proof calls. Read-only checks compare
encrypted bytes and authenticated journal projections before/after inspection.
Its strict checker binds the five exact status snapshots, eight actual caller
responses, proofs/certificates/source/artifacts and process lifecycles. Cumulative
lifecycle bounds allow the extra inspection children; per-child resource limits
and all prior proof/authority checks remain unchanged.

This combined gate uses an explicit separate synthetic grant cap 10 to allow
three positive payments plus fees (total9). The original cap 8 fixture still
refuses that ninth unit; a native regression test asserts exact cap refusal.
No production grant or proof constraint is raised. The first two retained-only
attempts remain failed (sequence comparison; original test budget exhaustion).
The standalone retained recipe and combined gate are distinct; qualification
must identify the actual registered clean source and completed recipe.

[The complete 36-check v2 gate](../evidence/protocol7-reconciliation/20261006/reconciliation-qualified-04.json) passes at clean unchanged
source `c0e0e7b15921a2d6f0723575f33771eaae724ecf`. Strict replay and 20 early-tamper
subcases pass. [Exact evidence and limits](../evidence/protocol7-reconciliation/20261006/AI_REVIEW.md)
include the authenticated complete-state restart and preserved earlier failures.
Same one-host/external-key/finite-synthetic-funds limits apply. No independent
ciphertext decryption, private-input attestation, rollback/latestness detector,
cross-device fencing, key recovery, discovery, merchant redemption, production
privacy or real-funds/public-network claim follows.

## Failed combined attempt and restart repair

The clean combined attempt at `74027d260c7d56e3de2093dc6460b72f288894a4`
is failed, not qualified:33 functional checks plus cleanup/source identity
completed (35 recorded). Replacement app3 startup timed out before the final
engine restart/convergence assertion. [Original evidence](../evidence/protocol7-reconciliation-attempts/20261005/reconciliation-failed-01.json)
is preserved; no strict completed-receipt replay or 16-subcase qualification follows.

The constructor still fully replays the checkpoint and validates its AppHash.
The repaired durable-block audit advances its own valid prefix with _execute
instead of replaying every growing prefix at each height. Every transition/proof,
row/result/request/vote/response check remains, with final reconstructed state
compared to the checkpoint. Readiness limits remain unchanged. The focused
native test passes using actual failed-run public history and explicitly
synthetic SQLite rows, including exact corrupted-response refusal. This is
not a same-store engine restart. Repeated prefix auditing is a likely timeout
cause. The fresh complete 36-check v2 run and strict replay now qualify
the repaired path within the same bounds; the original failed report remains failed.

## Strengthened restart acceptance

The v2 combined report adds a closed authenticated restart record. The runner
compares all four complete states at a quorum-held checkpoint, reopens node 3's
same private SQLite inode, records replacement application/engine identities,
and verifies a signed H+1 header for the complete post-restart state. The strict
checker independently replays that certificate, binds the checkpoint to the
final certified payment history and refuses noncanonical prefix substitutions.
Existing readiness/convergence limits are unchanged. A read-only AI review
found no remaining restart-specific defect; it is not external certification.

Run02 at c1ec545 was intentionally interrupted early before payment execution
to replace the receipt-only restart predicate; its raw failed status and logs
are [preserved separately](../evidence/protocol7-reconciliation-attempts/20261005/aborted-02/REASON.md).
The focused metadata test uses actual failed-run public history with explicitly
synthetic process/store identities and rejects seven substitutions despite
equal receipt lists. It does not prove engine convergence. The fresh complete v2
execution, independent certificate/proof replay and 20 early-tamper subcases
are now registered in the receipt linked above.
