# Segmented recipient ledger: execution and reproduction

The actual engine run used clean source
`3fed399b4f98b34cc1e220068c86fec8c51ac327`. The earlier negative run used
`9988571`: its first payment was correctly refused before block 1 committed.
The corrected runner waits for block 1 rather than relaxing payment validity.
Post-execution registration adds this evidence, documentation, the already tested
boundary-test file, and the byte-identical separately executed public verifier.
All executed application, worker, circuit, wire, profile and runner bytes remain
unchanged. This is self-review and separate verification execution, not an
independent external security review.

The later root source inventory adds P9 files without redefining the historical
P8 alpha v1 producer. `full-unit-02.log` exposed that the old checker derived its
membership from the mutable current inventory. The checker now uses the exact
252-member inventory from the trusted pre-P9 commit, with a hard-coded digest,
closed schema, exact membership equality and unchanged per-file byte checks.
`p8-pin-01.log` retains an intermediate checker return-value error;
`p8-pin-02.log` records all five corrected receipt methods passing, including the
51 existing coherent mutation cases and additional-member/pin-tampering refusals.
P8 runtime, wallets, circuits, producer files and historical evidence are unchanged.

## Actual results

- `ledger-02.json`: all 16 declared checks passed; four actual pinned validators;
  ten committed native payments and 21 notes; a payment after block 64;
  old-segment valid competing-spend refusal; same-store restart/rejoin.
- Static-quorum checkpoint at height 83, signed by header 84. This is AS-OF,
  without a freshness policy. A stopped node separately replayed to height 84.
- Direct application probe: 50 retained attempts, including 40 malformed refusals,
  at height 51. Those malformed attempts were not committed by the engine run.
- `public-check-01.json`: separate verification of all 11 public native proofs
  and the signed checkpoint. It is not a replay of public full history.
- `full-unit-01.log`: 1,757 methods, 1,597 passing and 160 skipped for unavailable
  older pinned native/receipt inputs. All 21 new ledger methods ran with a
  explicitly fake verifier; those establish storage/lifecycle boundaries.
- All produced engine, application and native children were reaped. No public
  service or ongoing background worker was left running.

## Prerequisites and commands

Use a trusted Linux/WSL host and the existing Python dependencies. The tested
interpreter was Python 3.14.4 with protobuf 6.33.6 and cryptography 46.0.4.
No command provisions infrastructure, imports keys, or installs dependencies.

Existing frozen native crates are `tools/recipient-consensus-bridge` (build the
verifier with `--no-default-features`), `tools/recipient-wallet`, and
`tools/recipient-transfer/halo2` (the prover build). The measured binaries and
their SHA256 digests are recorded in the engine receipt. Keep supplied executable
copies owned, executable and without group/world write permission. Native
profiles, parameter and verifying-key identities are checked at startup.

Build the new synthetic fixture offline:

```sh
cargo build --locked --offline --release \
  --manifest-path tools/segmented-fixture/Cargo.toml \
  --target-dir /absolute/path/to/fresh-owned-fixture-target
```

Run the actual gate with a fresh output name. The seed KAT below is the public
`fixture-first.tx` from a previously successful P8 run; the gate generates a new
pool, roster, bootstrap, KAT and native proofs. It never reuses production keys.

```sh
python -B scripts/run_protocol9_engine.py \
  --engine /absolute/path/to/pinned-cometbft \
  --worker /absolute/path/to/pinned-recipient-consensus-bridge \
  --helper /absolute/path/to/owned-recipient-wallet-helper \
  --fixture /absolute/path/to/owned-segmented-recipient-fixture \
  --prover /absolute/path/to/owned-recipient-prover \
  --kat /absolute/path/to/public-seed-first.tx \
  --output /absolute/path/to/fresh-public-ledger-report.json
```

Run separate proof/header verification against a full genesis digest supplied
through your trusted run/operator context. A digest copied from an untrusted
report does not create independent genesis authority.

```sh
PYTHONPATH=src python -B tools/release/check_segmented_ledger.py \
  --report evidence/protocol9-ledger/20261007/ledger-02.json \
  --worker /absolute/path/to/pinned-recipient-consensus-bridge \
  --genesis-sha256 87742462a7cf61a35a110a2a98b5a1df2f55556064ab846b22ff73b11c2465e8 \
  --output /absolute/path/to/fresh-public-check.json

PYTHONPATH=src python -B -m unittest discover -s tests -p 'test_protocol9_*.py' -v
PYTHONPATH=src python -B -m unittest discover -s tests -p 'test_*.py' -v
```

## Limits

This is a separately versioned backend development profile. The P8 wallet and
existing stores do not migrate. Segments retain an at-most-sixteen-note input set;
public anchors identify a segment prefix. Disk growth and restart replay remain
linear in retained history. Pruning, state sync, compact authenticated wallet
witnesses, protected production signing/custody, independent operators, hostile
network/host qualification, long-duration measurements, dynamic validator policy,
external specialist review, economics and public launch remain unassessed.

All assets and openings in this gate are synthetic. Public receipts and sanitized
logs are retained; private requests, validator keys and SQLite stores are omitted.

## Final root regression run

`full-unit-04.log` ran on clean source
`742cf4d86f9edea6e519577e10df7285a1f93592`: 1,760 methods,
1,600 passed and 160 skipped, with no failures or errors. Those older missing
native/receipt inputs remain unassessed. The earlier `full-unit-03.log` omitted
the required `PYTHONPATH=src`; its import/crash-test errors are retained. The
corrected invocation uses the documented source path. The final registration
adds these logs and this explanation only, without changing tested source.
