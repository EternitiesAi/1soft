# Device fencing and recovery boundary

This document records a security qualification of the current development P4
wallet. It does not add device fencing, replication, key revocation, or
production custody.

## What the local journal proves

One P4 wallet serializes writers through its SQLite journal. Approval rechecks
the authenticated checkpoint, exact review, signer role, nonce, grant and
budget limits before unlocking a vault and recording the original signed bytes.
Delivery consumes one exact attempt before network I/O. A timeout or lost reply
therefore remains unresolved until an independently authenticated receipt is
imported. Recovery returns historical bytes and does not sign, submit, renew
trust, or release a hold.

These are guarantees for one intact journal on a trusted host. A backup archive
is intentionally recovery-only. Its inspection fields must continue to report
`current_spending_authority: false`, `signing_enabled: false`,
`dispatch_enabled: false`, `automatic_resend: false`, and
`old_device_fenced: false`.

## Forked-device result

The qualification test clones one authenticated journal at a common checkpoint,
then approves different transfers on two independent copies. Both local copies
can produce different signed wires with the same grant nonce. This is expected:
the journals have no shared lock, device epoch, or online reservation service.

The native grant nonce remains the chain-level collision boundary: when both
wires are applied at the same next height, one can be accepted and the other is
rejected. The losing local copy must not infer that it was unpaid or release its
hold. It remains pending until an exact authenticated receipt or other explicitly
qualified reconciliation path is imported.

The test also rotates the canonical account key after cloning. The stale clone
can still prepare and sign from its historical checkpoint because it has not
observed a new chain proof and there is no physical device fence. The resulting
wire is not broadcast; applying it to the post-rotation native state is rejected.
This separates the missing physical/device fence from the effective on-chain key
rotation boundary.

Run from the protocol4 wallet test environment:

```sh
PYTHONPATH=tools/protocol4-wallet/src:tools/protocol4-wallet/tests:tools/protocol4-delivery/src:tools/protocol4-evidence/src:tools/protocol4-custody/src:tools/protocol4-client/src:tools/protocol4-client/tests:tools/validator-transition/src:src \
  python -m unittest discover -s tools/protocol4-wallet/tests -p 'test_forked_device_security.py' -v
```

## Required production design before claiming cross-device safety

1. Bind every signing journal to a canonical wallet identity and monotonic
   device epoch, with authenticated online or threshold coordination before
   approval.
2. Make key rotation publish a revocation/fencing event that every signer must
   observe before approval; define behavior while the device is offline.
3. Add provider or chain status queries and an idempotency key so ambiguous
   submission can be reconciled without blind resend.
4. Add encrypted-backup rekeying and compromise recovery. The current archive
   uses authenticated encryption, but passphrase compromise has no revocation
   or re-encryption ceremony.
5. Qualify crash ordering, power loss, rollback, clock rollback, copied
   journals, concurrent approvals, rotation races, one chain winner, losing
   obligation retention, receipt import, and recovery after every transition.

Until those gates exist, reports must say **local journal coordination only**,
**historical recovery only**, and **old device not fenced**. A balanced local
accounting record is not proof of reserves, solvency, custody, or global
exactly-once execution.
