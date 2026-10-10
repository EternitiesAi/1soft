# P9 wallet native journey reproduction

Actual engine/caller source: 9122c0d5ee33f3245eae15bf07b8b961a5db895a.
Tree: 1c4b1401a0bc7af7763994ae608359cd289784fb.
Later source registration adds documentation, sanitized public evidence and source
inventory only; the executed wallet, caller, verifier and runner bytes are retained.

Use the installed pinned CometBFT 0.38.25, verifier-only recipient-consensus-bridge,
segmented-fixture, recipient-wallet helper/prover and an existing public relation8
KAT in a trusted owner-controlled Linux/WSL workspace. Private worker executables
must satisfy the existing protected worker checks. No install/download is needed.

```sh
env PYTHONPATH=src /path/to/qualified/python -B scripts/run_protocol9_wallet_engine.py \
  --engine /path/to/pinned/cometbft \
  --worker /path/to/recipient-consensus-bridge \
  --helper /path/to/pinned/recipient-wallet-helper \
  --fixture /path/to/pinned/segmented-fixture \
  --prover /path/to/pinned/recipient-wallet-prover \
  --kat /path/to/public/relation8-kat.tx --output /path/to/new/receipt.json
```

The output and its `.artifacts` directory must be absent. The runner creates its
own disposable four-validator homes, public proofs and owner-only encrypted wallet
files. It removes only that owned temporary runtime after stopping its processes.
Do not substitute production keys, real funds, public ports or persistent stores.
The fresh genesis binds the actual four-key engine roster and native bootstrap.

`native-02.json` passed all 19 declared checks. Both native payments executed,
including a recipient spending received funds. Alice's real loopback submission
was forwarded once and its response dropped. Recovery used signed exact history;
resending was refused before I/O. Signed state/header heights were 2/3, 5/6 and
9/10. The fresh Python child reopened both externally keyed encrypted wallets
with fresh native replay. Keys and openings entered the child only through a
bounded private pipe and were never retained in logs/artifacts. All 18 recorded
engine/app processes and the cold child stopped; native calls were reaped.

The first actual run, `native-01.json`, failed in the negative test harness after
both payments, recovery and conservation. Wrong-owner native inspection returned
the intentionally suppressed `Unavailable` error rather than ValueError. The fix
recognizes only a reaped unsuccessful inspect-note without timeout, checks an
unchanged wallet, then verifies a valid owner inspection with the same helper.
Other unexpected worker failures still fail the gate. No acceptance check changed.

`import-identity-red.log` records a separate failing regression: a caller could
select another commitment in the same segment while importing an opening. The
new explicit commitment equality check passes the regression. Envelope, static
signature, storage and dispatch-order unit tests label fake native operations;
they are not proof/consensus passes. Initial root regression at c8019ff ran
1775 methods, 1615 passed/160 skipped, with existing SQLite resource warnings.
The final root log and delivery result register the final source and counts.

This is self-review and separate verification execution, not independent external
security review. The complete history algorithm is linear and client-bounded.
The wallet gate used five ledger notes and two payments. More-than-sixteen global
note selection is separately tested as unit mechanics; native wallet rollover,
post64 wallet operation and maximum capacities remain unassessed. The earlier
backend's native 21-note gate is a distinct preserved receipt.

No Actions, paid compute, public deployment, website/DNS changes, real funds,
production custody keys, force-push or Resident/Luna work. Old profiles, stores,
runtime and historical public evidence are preserved. No validator homes, wallet
plaintext/openings/keys, private stores or native binaries belong in this evidence.
