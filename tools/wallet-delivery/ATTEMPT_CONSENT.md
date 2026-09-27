# Delivery approval belongs to one attempt

September 27, 2026. Follow-up to the exact published Astra line, PR #12:
`dd096271f24e704d27f39d551d5f16986934481d`, tree
`5e1e7385033bdfa1f5e31821c7be8d1b101a2a40`.

## What changed

The original delivery confirmation identified the already signed payment, payer,
grant and route. It did not bind a particular send/replay attempt or the wallet
checkpoint and obligation inventory displayed during that review. The new
version-2 confirmation additionally binds those facts. This tightens local
submission consent; the native chain already rejects duplicate execution and
overspending. No on-chain double-spend result is claimed.

PR #11 at `4d314070b44bec83b7fbaf7747f1536ae98f3dab` was inspected specifically
for its review/send boundary. It has a related context-bound approval design,
but remains a different implementation. This change integrates the narrow
behavior into PR #12's existing DecisionDelivery class; it does not merge either
branch, replace the client, or inherit PR #11's tests or network results.

No native monetary rule, signature domain, transaction byte, wallet reservation
schema, application-state format, or RPC transport implementation changes.
Codex's sidecar-alias and dispatch-configuration guards are retained.

## Approval scope

Each review identifies the original wallet decision and signed wire bytes,
explicit account/grant, recipient, amount, native fee, total debit, nonce,
validity height and selected local route. It also includes:

- `operation`: first `send` or explicitly requested `replay`;
- `next_attempt`: one next value of the existing durable dispatch counter;
- the current transport status, verified wallet checkpoint, and complete local
  obligation-inventory digest, not a truncated display list.

The v2 digest uses a different domain from the old delivery confirmation. Old
v1 confirmation strings are refused; existing signatures and databases are not
migrated or replaced. A confirmation is a consistency binding, not proof of a
human identity, a password, a hardware approval, or a new transfer signature.

Before I/O, send rechecks the already signed payment against authenticated saved
state, derives the current review, and compares the supplied digest. The existing
dispatcher then commits its attempt before contacting RPC. Its process lock still
serializes users of the same delivery journal. Recording an attempt consumes the
review's scope even if the process exits before a socket is opened or no reply
comes back. A failed database commit that records no attempt does not consume it.

A new signature elsewhere in the same wallet inventory or a newer observed state
invalidates the earlier review. The user must review the unchanged payment again;
there is no automatic amount, nonce, fee, role, policy, or expiry update. A fresh
review cannot override a revoked or expired native grant.

## API and CLI

`queue` preserves its staging behavior. While still at an unattempted queued
payment, it returns a first-send `submission_review` and `delivery_confirmation`.
Repeated queueing after an attempt returns status only; it never supplies replay
consent. `status`, send results, refresh results and reconciliation results return
`delivery_confirmation: null` and `submission_review: null`.

The explicit review interface is:

```python
# The payment is already signed and queued in the existing journals.
review = delivery.review(decision_id, account=account, grant_id=grant_id)
result = delivery.send(
    decision_id, review['delivery_confirmation'], account=account, grant_id=grant_id
)
# No automatic replay follows an unresolved result.
```

An explicitly chosen exact-byte retry has a separate review:

```python
review = delivery.review(decision_id, account=account, grant_id=grant_id, replay=True)
result = delivery.send(
    decision_id, review['delivery_confirmation'], account=account,
    grant_id=grant_id, replay=True
)
```

The CLI adds `review` and `review --replay` to the existing required genesis,
policy, wallet, delivery-journal, payer/grant, decision and endpoint arguments.
Use the confirmation from that review with `send --confirm` or `replay --confirm`.
The next retry needs a newly reviewed digest. No vault/password input, raw-envelope
import, new outbox, financial reservation, RPC read, or signing operation is
introduced by review. Its local read transaction does not modify wallet tables.

## Recovery and limits

Receipt collection still does not release the financial hold. Only the original
wallet's full-state/ancestry/freshness/obligation verification reconciles it.
Historical inspection and original-byte recovery remain available without making
an old report into current spending permission.

This is one-journal coordination, not globally exactly-once submission. Another
delivery journal can submit the same signed bytes. The native application rejects
repeat execution; it does not prevent that second network submission. Old binaries,
raw-key use, direct dispatcher access, separate devices, cloned journals and whole-
workspace rollback can act outside this version's review rules.

There is no transaction spanning the wallet snapshot and the network. Another
signer may act AFTER the final source read. A negative-control test demonstrates
that boundary rather than claiming to eliminate it. Native execution remains the
final authority on balances/counters/permissions. SQLite read transactions see a
consistent snapshot, not changes made after that snapshot was captured:
https://www.sqlite.org/lang_transaction.html .

No new dynamic-validator trust, proof of latest network state, public endpoint,
production custody, USD backing, external settlement, or independent audit is
established. Full witness and inventory checking remains bounded but potentially
expensive; this change is not a performance optimization.

## Source and verification scopes

The refreshed Codex archive matched
`8395c131a62166dbcf57812b4c07f8a24c77fb118c1b182f71179e7b477576ee`.
All 294 payload manifest entries matched, including 219 tracked source files and
68 final evidence files. The source reconstructs the exact PR #12 tree above.

The saved four-validator reports contain 22/39/62/67 passing checks for their
original dd096 source. This review reverified the saved certificates and client
receipts, replayed all 28 certified native transactions from genesis, reproduced
all four final states/app roots, and checked the saved compact witnesses. Delivery
log wire hashes match the certified transactions. The original engine binary was
not rehashed and the original network processes were not independently observed.
Transport counts remain attributed log observations, not cryptographic proofs.

New execution on this follow-up source:

- All 974 standard core tests passed in 31 complete isolated module processes.
- All 83 delivery tests passed in four complete groups: 51 inherited plus 32 new.
- All 45 standard account-view tests and 30 separate JavaScript reference tests
  passed. Optional unpublished catch-up dependencies were not substituted.
- Four behavior probes passed on the intact implementation. Four individually
  weakened disposable copies were rejected by assertion failures: attempt number,
  local inventory, wallet checkpoint and confirmation comparison.

The runnable local example queues both signed payments before delivery, drops
responses after actual fixture execution, keeps holds during receipt collection,
rejects Atlas's now-stale approval after Raven reconciles, then reviews and sends
Atlas's original bytes. It ends at pending 0, native budget spent 100, exactly two
submissions and two original signatures. Fixture key files were removed before
delivery. Committee attestations are synthetic, not a new validator run.

The 32 new cases cover CLI use, unchanged signatures, stale reviews, explicit
retry scope, wrong-role/type inputs, no key access, failed commits, an actual
process exit after attempt commit but before I/O, receipt/hold separation, and
explicit local-only coordination limits. One inherited positive replay test now
requests the explicit retry review before submitting the same bytes.

The first full baseline invocation exceeded the tool deadline; it is excluded.
All 51 baseline tests subsequently passed in four completed groups. The first new
run exposed a fixture thread assertion for a correctly rejected duplicate; that
run's raw output is retained. The fixture now reports the actual native rejection
code, and the corrected test explicitly checks no second debit. This was test-
harness handling, not acceptance of a duplicate native payment.

## Next actual-network gate

The opt-in real-validator runner now obtains a fresh delivery review before each
payment. After Raven reconciles, it explicitly checks that the old Atlas approval
causes no new proxy submission, then submits the same Atlas bytes using its new
review. Existing reply-drop, receipt-only hold, reconciliation, quorum and exact-
byte checks remain in place. Default non-delivery paths are unchanged.

That updated runner is authored and covered by the standard runner tests, but a
new actual-validator run has NOT executed in this runtime: no pinned engine is
installed, and ordinary module-host DNS resolution failed. Codex's previous
22/39/62/67 results apply only to dd096, not automatically to this follow-up.
No Actions, paid compute, public deployment, real funds, DNS/site changes,
Resident/Luna/Psyche work, force-pushes or merges are part of this checkpoint.
