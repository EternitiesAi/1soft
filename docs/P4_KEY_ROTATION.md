# Replace a P4 owner key

1soft can replace an available account owner's signing key while keeping the same
account, balances and receipt history. Both the incoming key and current owner
must approve the complete intention. This development workflow uses existing
native account rules; it does not introduce a chain upgrade or lost-key recovery
quorum. If every copy of the owner key is lost, a journal backup alone cannot
authorize replacement.

## Review, consent, owner approval

Use one canonical P4 wallet journal for all payments and rotations on these funds.
First sync independently pinned, recent full evidence through the existing wallet
workflow. Then use `tools/protocol4-wallet/scripts/p4_rotation_cli.py` with global
`--genesis`, `--policy` and `--wallet` arguments:

1. `prepare --payer ACCOUNT --new-public-key PUBLIC_KEY --valid-until HEIGHT
   --output NEW_REVIEW` creates an unsigned private review. Read the account,
   current owner key, incoming key, nonce, fee, expiry, checkpoint, pending units
   and original grant IDs before consenting.
2. `accept --review NEW_REVIEW --confirmation REVIEW_DIGEST --vault INCOMING_VAULT
   --output NEW_ACCEPTED_REVIEW` asks the incoming encrypted vault to consent.
   The incoming consent binds the entire native rotation body. This phase does
   not reserve funds or sign as the old owner. Read the accepted review and its
   new confirmation digest before owner approval.
3. `approve --review NEW_ACCEPTED_REVIEW --confirmation ACCEPTED_DIGEST
   --vault CURRENT_OWNER_VAULT --output NEW_SIGNED_WIRE` revalidates the current
   wallet state before unlocking the owner key. It saves the exact original
   owner-signed wire and fee reservation in the same journal as payments.

Passwords are read only through a local terminal with echo disabled. They cannot
be passed through command arguments, an environment variable or a pipe. Outputs
are private, exclusive files; existing files and wallet sidecars are preserved.
No command above sends a transaction. Password prompts do not hold a SQLite lock.

If output fails after owner approval, the decision stays saved. The accepted
review digest is its stable decision ID, also printed before wire publication.
Use `recover --decision-id ID --payer ACCOUNT --output NEW_WIRE` to export that
original wire. Do not sign another rotation to repair a lost return.

## Delivery and confirmation

The existing `P4Delivery` workflow can prepare and submit the selected owner-role
rotation through explicit decision-bound confirmation. Its one-shot submission
claim is committed before network I/O. A lost response stays unknown and cannot
reset that claim. Endpoint admission does not prove execution.

While rotation remains unresolved in the wallet, new payments by this payer and
submission of its previously signed payments are paused. Historical inspection,
original-wire recovery and positive receipt collection remain available. This is
local journal coordination; external signers, copied journals and other software
can still act, and already submitted transactions can still execute.

`status --decision-id ID --payer ACCOUNT --evidence FRESH_EXTENDING_PACKET`
verifies the complete evidence and exact positive receipt without changing the
journal. It derives the key and epoch at the receipt boundary, then reports the
current checkpoint owner separately. A later rotation back to the old key must
make `old_owner_retired_at_checkpoint` false. Original grant epochs remain
separate from any new authorization using the same public key.

The report's physical-device-fencing and latest-state guarantees are always
false. It cannot erase hardware keys, know every device, renew fixed trust,
prove global coordination or assert permanent retirement of a public key.

Only explicit positive-proof reconciliation through the existing live wallet
retires the rotation fee hold. Every unrelated uncertain payment remains held,
including old-epoch or expired payments. Do not discard a journal to release
these conservative holds. Incoming consent alone never releases anything.

Encrypted custody backups can preserve the new rotation decision and its
original wire alongside payment holds and consumed delivery claims. Restoring a
backup still produces a recovery-only archive, with no signing, dispatch, new
proof import, activation or restored private keys. An older client that only
understands transfer reviews rejects a rotation-bearing journal/archive.

## Verification scope

The focused wallet tests exercise actual native/application rules, encrypted
vaults, concurrent SQLite writers, full signed-proof replay, later key reuse,
private CLI outputs and owned password terminals. Committee signatures in those
fixtures are synthetic; those tests do not execute consensus.

The separate `scripts/run_protocol4_delivery_engine.py --key-rotation` profile
appends owner replacement to the existing full-turnover delivery scenario using
an independently SHA-pinned CometBFT v0.38.25 binary. It keeps every original gate,
qualifies real rotation and replacement-owner payment execution, checks actual
CheckTx rejection of old authority, and retains the six unknown diagnostic units.
Only an actual returned result qualifies that profile for its exact source.
All listeners and operators remain on one host with disposable keys and funds.
Independent operators, hostile-host resistance, external security review,
production recovery, economics and public launch remain separate gates.
