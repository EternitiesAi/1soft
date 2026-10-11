# P9 history wallet v2 execution receipt

Native/public/root source `449652754b770c75c430bf33ee438d92bf1db365`; tree `ae6c2fcedfa85ced334d5f30fff1ca01a0df9643`.
All28 actual native checks passed. Three encrypted-wallet payments and seven
setup-generator payments produced21notes/10fees. Twelve further signed states
advanced both wallets, retaining exact original results/wires and single-attempt
markers. Signed state heights:[1, 5, 65, 68, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83]. Both encrypted wallets reopened in a fresh
Python process. All owned processes stopped; native calls reaped without timeout.

The first native attempt passed the payment journey but refused the new update
loop because the runner left two source engines paused. That failure, source and
cleanup receipt are preserved as native-01. The runner now restores all four
engines before every next observation; the complete rerun is native-02. No wallet
or consensus checks were relaxed, and wallet/consensus code stayed unchanged.

Storage below compares the same retained observation/obligation payload against
an equivalent representation with duplicated complete-history packets. Compact
and duplicated measurements are plaintext serialized bytes; encrypted file bytes
are actual file sizes. This does not claim measured encryption-to-encryption
comparison or incremental native proof authentication.

```json
{
  "alice": {
    "compact_plaintext_bytes": 152716,
    "encrypted_file_bytes": 306439,
    "equivalent_duplicated_plaintext_bytes": 290419,
    "history_blocks": 83,
    "plaintext_reduction_bytes": 137703,
    "retained_observations": 5,
    "stored_histories": 1
  },
  "bob": {
    "compact_plaintext_bytes": 135107,
    "encrypted_file_bytes": 271221,
    "equivalent_duplicated_plaintext_bytes": 277420,
    "history_blocks": 83,
    "plaintext_reduction_bytes": 142313,
    "retained_observations": 3,
    "stored_histories": 1
  }
}
```

Separate full-native public replay verified17 signed states/ten exact receipts.
Root:1819 methods/1659 passed/160 skipped,
zero failures/errors, 299.878 seconds. Existing SQLite warnings retained.
The initial14 explicit missing-feature assertions failed; the implemented30
focused tests passed. Fake proof-worker storage units are separate from this
actual native cryptographic/CometBFT gate. Self-review, no independent security audit.

Full signed bounded native replay remains authoritative. Limits remain4096blocks/
512attempts/6MiB and32notes/16obligations/8observations/256revisions/16MiB plaintext.
One trusted host, four validators, disposable keys and synthetic funds. Hostile
host/local rollback, full capacity/long duration, independent operators, production
custody, public launch, browser migration, state sync/pruning/economics/external
review remain unassessed. Public data does not independently verify hidden input
binding, private balances, transport/custody or encrypted storage measurements.

Raw public engine/app logs sanitize only the owned temporary runtime path; other
raw log bytes/warnings are preserved. No AES keys/private openings/wallet stores,
validator homes/native binaries/credentials/Git bundles are included.
See docs/PROTOCOL9_HISTORY_WALLET.md for reproduction and scope.
