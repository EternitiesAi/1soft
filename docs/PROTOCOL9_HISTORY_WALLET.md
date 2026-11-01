# P9 one-copy history wallet v2

The separately versioned `protocol9_history_wallet.RecipientWallet` stores one
complete history and the exact signed checkpoints/certificates required by
original payments. It inherits the frozen v1 payment, note-origin, proof, hold,
single-send and result rules. Existing v1 wallets refuse v2 and vice versa; no
migration or key repinning is performed.

## Storage and authority

An observation used by a preparation or exact result keeps its slot forever.
Only an unused last slot can be replaced after the new state authenticates and
extends the previous full history. All earlier slots remain fixed. If the last
slot is required and all eight slots are occupied, the update refuses without a
write. This is bounded capacity reuse, not unlimited history or payment retention.

The storage codec is not a verifier. On open, every retained prefix is rebuilt
from the stored history and authenticated through complete signed native replay.
No persisted derived index, supplied spent set or model memory is authoritative.
Original private requests, exact wires, attempt markers and result dictionaries
are still rechecked. Authentication remains linear and bounded, not incremental
or compact proof verification. Encryption and host ownership rules stay intact.

## Sparse history packets

A history packet (`1soft/protocol9-sparse-history/v2`) lists only the blocks that
hold attempts. An empty block touches no index, only the height and the history
hash, so the verifier rebuilds it (`Store.skip_empty`) and the signed checkpoint
still binds every height: leaving out, adding or moving an attempt-bearing block
changes the replayed checkpoint and is refused. The v1 packet listed every block
under a 4096-block cap. Because the app hash moves with the height, the engine
never stops making blocks, so an idle ledger outgrew v1 in about an hour.

v2 bounds the blocks with attempts at 4096 (and attempts at 512, as before) and
the replayed height at 2^20, about ten days at 500 ms blocks. Replaying 2^20
empty heights took 1.9 s on one Ryzen 9 9900X core. v1 packets and wallets
holding v1 packets are refused; no migration is performed.

## Native acceptance and reproduction

The additive runner repeats the prior three-wallet-payment/seven-setup-payment
journey, old/new segment spending after height64 and exact lost-reply recovery.
It then obtains twelve additional real quorum-signed observations, verifies all
original results/wires/attempt markers, measures one-copy storage, and reopens
both encrypted wallets in a fresh Python process. All28 checks must pass.

```sh
python scripts/run_protocol9_history_wallet.py \
  --engine /owned/pinned/cometbft --worker /owned/pinned/recipient-consensus-bridge \
  --helper /owned/pinned/helper --fixture /owned/pinned/fixture \
  --prover /owned/pinned/prover --kat /public/seed-kat.tx --output /receipts/native.json
python tools/release/check_protocol9_history_wallet.py \
  --receipt /receipts/native.json --worker /owned/pinned/recipient-consensus-bridge \
  --output /receipts/public-check.json
```

Use fresh outputs, a clean checkout, externally pinned installed binaries and a
Python interpreter with the project's actual protobuf/cryptography dependencies.
The separate public checker replays17 signed states and ten exact native receipts.
Result observation numbers are wallet-local stable slots, not report-list indexes.
Public data does not independently reveal hidden input/amount binding, custody,
transport behavior or encrypted storage; those are private-runner measurements.
Storage comparison uses the same retained observations and fields serialized
with duplicated history versus one copy. Encrypted size is the actual file size.

## Limits

The [native receipt](../evidence/protocol9-history-wallet/native-02.json)
passed all28 checks at `449652754b770c75c430bf33ee438d92bf1db365`. The separate
[public replay](../evidence/protocol9-history-wallet/public-check-01.json)
verified17 signed states and ten exact native receipts. Storage and root regression
measurements are recorded in [the execution notes](../evidence/protocol9-history-wallet/REPRODUCE.md).
One trusted host/four validators/disposable keys/synthetic funds. Client4096
blocks/512attempts/6MiB; wallet32notes/16obligations/8observations/256revisions/
16MiB plaintext, possibly exhausting byte capacity first. No caps are relaxed.
Maximum capacity, long-duration load, hostile host/local rollback, production
custody/key recovery, browser v2 migration, independent operators, state sync,
pruning, economics and external cryptographic/security review remain unassessed.
No Actions, paid compute, public deployment/DNS changes, real funds, production
keys, other project work, old-store migration or force-push are part of this gate.
