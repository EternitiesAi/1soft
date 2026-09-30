# P4 local ledger

A read-only local explorer for verified Protocol 4 checkpoints. Accounts, shared
budgets, grants, successful transfers and dynamic validator rosters all come from
one replay of the original proof under separately pinned genesis and a fixed
trust policy. State H is anchored by signed header H+1. This is historical state,
not the latest network state or a spendable wallet balance.

## Run

From the repository root with the pinned Python environment:

```sh
python tools/protocol4-explorer/scripts/p4_explorer.py \
  --genesis /private/engine-genesis.json --policy /private/read-policy.json \
  --store /private/p4-read.sqlite serve
```

Open the printed `http://127.0.0.1:PORT`. The input store must already exist and
contain a checkpoint accepted by `tools/protocol4-client/scripts/p4_read.py`.
Use `inspect` instead of `serve` for the same projected state as JSON. The explorer
does not collect RPC data, import proof, sign, dispatch, or create a wallet.
Explicit refresh replays original evidence again; there is no polling.

SQLite may create its normal WAL/SHM coordination sidecars while opening an
existing WAL-mode store read-only. The explorer does not modify accepted evidence,
main-database contents or wallet journals. Literal loopback binding and exact
Host/origin checks limit browser access. Assets are local, with no analytics,
external fonts, remote resources or user-supplied HTML.

## What the values mean

Money is displayed as integer native atomic units; genesis defines no decimal
scale or fiat price. Account key epochs differ from validator epochs. Budget
remaining is cap minus recorded usage, not a reservation or spend permission;
owner epoch, expiry, recipient constraints and linked budgets also matter.
Missing records stay unavailable, never zero, unpaid, absent or retryable.

Payment details expose an explicit proof-capsule download. **A capsule contains
complete proof history and unrelated accounts, balances, grants and transactions,
as well as the original signed wire. Review that disclosure before sharing.**
There are no private signing keys in the capsule. The separate
`tools/protocol4-receipts` verifier requires externally supplied genesis, policy
and a current clock still within the original fixed trust interval.

The browser receives only a display projection, not complete evidence, envelopes
or administrative/rejected attempts. The internal `project_report` helper accepts
an already verified report; it is not a proof-ingestion API. Only `snapshot_view`
and `current_view` validate original evidence for callers.

Twenty-row pagination bounds account/payment/budget rendering. Grants have an
explicit first-20 preview; validators are already bounded by the native registry.
No compact proof, historical expiry override, spending control, independent-host,
external settlement or production-readiness claim is added.
