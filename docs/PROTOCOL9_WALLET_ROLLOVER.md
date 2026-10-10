# Native P9 wallet segment rollover and post64 rehearsal

This additive gate exercises the unchanged P9 wallet on four actual pinned
CometBFT0.38.25 validators on one trusted Linux/WSL host. The previous two-payment
wallet receipt and ten-payment backend receipt keep their original scopes.

## Acceptance

The runner makes three payments through encrypted wallets. Seven separately
identified synthetic generator payments create rollover. Alice's first reply is
discarded after one actual forward; signed exact execution resolves the original
without resend. After the ledger has 17 notes and height exceeds64, Alice spends
change in segment0; Bob spends change in segment1. Both actual wallet payments
must execute after64. A distinct valid native competing spend of the older input
must be refused by all four applications. Final checkpoint has21notes/10fees.

Five signed full-history observations are authenticated. The run checks spent
input refusal, exact retained obligations, tampered history/header/owner/rollback
refusal, synthetic conservation and encrypted reopening in a fresh Python process.
Private input reaches the reopen child only through bounded stdin. All owned
processes stop; source stays clean/unchanged. No wallet/client caps are increased.

## Reproduction

Use a clean checkout, pinned installed binaries and the actual Python interpreter
with protobuf/cryptography dependencies. All paths below are explicit caller
inputs; output receipts and artifact directories must be fresh.

```sh
python scripts/run_protocol9_wallet_rollover.py \
  --engine /owned/pinned/cometbft --worker /owned/pinned/recipient-consensus-bridge \
  --helper /owned/pinned/helper --fixture /owned/pinned/fixture \
  --prover /owned/pinned/prover --kat /public/seed-kat.tx --output /receipts/native.json
python tools/release/check_protocol9_wallet_rollover.py \
  --receipt /receipts/native.json --worker /owned/pinned/recipient-consensus-bridge \
  --output /receipts/public-check.json
```

The separate public checker validates artifact/runtime pins and replays all five
signed observations with the actual verifier. It derives the ten exact receipts
and old/new input locations; public proof verification does not independently
reveal private balances or demonstrate transport/custody behavior. Those latter
exercises are recorded by the native runner. Tests of report refusal use no fake
native qualification.

## Scope and limits

Execution evidence is pending until an exact completed receipt is registered.
One host, disposable keys and synthetic funds. Complete history replay is linear
and bounded, without compact proofs or freshness. Client4096blocks/512attempts/
6MiB; wallet32notes/16obligations/8observations/256revisions/16MiB plaintext, with
byte capacity possibly exhausted first. Maximum-capacity/long-duration behavior,
independent operators, public network faults, production custody, hostile host,
local encrypted rollback, key recovery, browser migration, pruning/state sync,
economics and external cryptographic/security review remain unassessed.

No Actions, paid compute, public deployment, DNS/site changes, real funds,
production keys, other project work or force-push are used for this gate.
