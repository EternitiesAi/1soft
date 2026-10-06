# P8 recipient wallet

This is a finite development wallet for the separately pinned P8 recipient
protocol. It preserves the P1–P7 source and the frozen P8 proof relation/profile.
It has no network dispatcher or public wallet API.

The completion gate is a fresh four-validator local CometBFT network with:

- a genuine received payment authenticated by replay and a signed next header;
- exact opening import, tamper refusals, encrypted cold reopening and idempotent import;
- arbitrary payment construction from the retained opening using native root/path,
  nullifier and successor-origin derivation, followed by genuine proving;
- one deliberately discarded broadcast response, original-wire certificate
  recovery, byte-stable repeated recovery and no second submission;
- private output delivery to a separate recipient wallet using only the destination
  public key at the sender;
- a distinct genuine conflicting spend followed by signed conflict reconciliation
  that retains the original obligation and refuses regeneration;
- finite process cleanup, unchanged source and sanitized public evidence.

`protocol8_wallet.RecipientWallet` requires an external 256-bit AES key, opaque
wallet ID and canonical nonzero recipient secret on every open. The private
recipient secret is never the destination argument to the sender. A private
helper derives the recipient's public H810 key commitment from its own secret.
No account discovery, mnemonic recovery, key management or human identity is
implemented here.

The AES-GCM envelope binds the complete genesis digest, bootstrap, frozen profile,
parameters, verifying key, worker/KAT/helper pins, wallet ID and recipient key.
Its one encrypted snapshot contains immutable note openings/origins, signed
observations, fixed proof requests and payment obligations. Locking and atomic
replacement target one trusted POSIX host. Files and parent directory require
owner-only permissions; symlinks, hard links and plaintext database sidecars
are refused. A finite nonce history prevents reuse within the retained snapshot.
It does not prevent hostile-host memory access, deletion or restoring an old
encrypted snapshot, and it is not production custody qualification.

An import reproduces the opening's exact certified output commitment. The
successor origin is private off-chain delivery material: the public wire does
not disclose the consumed input's origin, so the receiver cannot derive that
origin from public fields alone. Native commitment reproduction authenticates
the delivered origin. Explicit genesis import is a separate externally pinned
issuance path. Signed AS-OF observations must monotonically extend the retained
full block history; a same-height divergent state or regression is refused.

Preparation requires an imported note, unconsumed AS-OF nullifier/intent, native
authenticated root/path, positive payment/change/fee and a bounded validity
window. The wallet uses `observed height + 2` as the earliest candidate execution
height and caps its exclusive upper bound at 64 as a conservative wallet policy.
This is not a statement that the observation is globally fresh or that a later
validator will accept the transaction.

The encrypted obligation is persisted before proving, and the verified exact
public wire is persisted before returning its identifier. An uncertain prover
result remains held without a wire; this version deliberately has no reproof or
abandonment path. `mark_attempt()` persists a single caller attempt marker and
does not itself dispatch. Trusted callers must mark before sending and must not
send again after a lost reply. Certified reconciliation checks the exact raw
wire, statement, transaction ID and receipt. A spent nullifier or consumed intent
from another wire yields `conflict-held`, without releasing or retrying.

Limits: eight notes, eight obligations, eight signed observations, 96 revisions,
four MiB private payload, and the existing consensus limits of 16 typed notes,
32 attempts and 64 block heights. Storage exhaustion fails before replacement.
Successful test receipts establish only the measured one-host development case.
State sync, P7 migration/allowance composition, independent operators, production
funds, adversarial cryptographic audit, scalable storage, metadata privacy and
public deployment remain unqualified.
