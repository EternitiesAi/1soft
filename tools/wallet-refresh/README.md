# 1soft read-only wallet refresh client

This is new, optional client code. It leaves the repository's native/ABCI rules,
existing wallet, PR #7 source, root test inventory, and deployed website unchanged.
It neither contains nor substitutes for the previously blocked catch-up module.

**Dependency:** the complete local Codex catch-up source returned on 2026-09-27,
declared commit `4fbebc8461b80538a85cf14b181f282ff60583f9`, tree
`af1963fe7b16fa0be030ccee47c731795cbfad71`. That source is in the owner's return
ZIP, not in PR #7. This add-on is not a standalone complete node or a claim that
all dependencies have been published. No blocked source has been encoded, renamed
or uploaded by this PR.

## Behavior

`refresh_wallet(wallet, endpoint)` captures one state target, verifies its signed
commitment and native records, fetches consecutive header batches, and asks the
existing shared wallet to reconcile that full state. It resumes from already
committed header progress instead of resetting the journal. It never signs,
unlocks, submits, retries a payment or renews an expired trust policy.

Header-only progress cannot retire a hold. Missing evidence, failed reads and
invalid certificates cannot mark funds available. A final full-state sync must
still pass the existing freshness, ancestry, exact-receipt and obligation checks.
If the target becomes stale while catching up, verified header progress remains
but spending authority is not refreshed. Changes by another wallet connection are
rechecked before each commit; no database lock is held during HTTP.

Only a literal `http://127.0.0.1:PORT/` endpoint is supported. One explicit call
requests at most two snapshot reads plus four batches of at most 64 headers. The
default is two batches. Collection jobs have a 15-second process deadline, header
batches a 2 MiB limit, and snapshots a 4 MiB limit. The existing HTTP reader rejects
redirects, proxies, compressed responses and ambiguous framing. No background
polling, public endpoint or automatic dependency download is provided.

The CLI exits zero only for `state_synced: true`. `headers_only`, `unavailable`,
`rejected`, `target_behind_wallet` and `concurrent_progress` are not completed state
sync. Even `synced` means one authenticated historical checkpoint, not guaranteed
latest chain state or production financial authorization.

## Local checks

With installed pinned dependencies and the complete returned native source:

```sh
python tools/wallet-refresh/tools/verify.py --native-root /absolute/path/to/returned/source
```

Both source inventories are checked first. Eight isolated add-on integration tests
passed against the unmodified returned core. For the CLI, set `PYTHONPATH` to the
returned source's `src` directory before calling `scripts/refresh_wallet.py --help`
inside this add-on. Genesis, policy, journal and endpoint are explicit inputs. No
password, vault or broadcast option exists.

## Evidence scope

The full integrated conversation package passed 1,061 Python cases, zero skips,
failures or errors, in 45 isolated groups; 42 new refresh cases are included in
that total. These include a 130-header HTTP catch-up with 64/64/2 batching, restart,
actual process exit after a batch, pending-hold preservation and final native
reconciliation. Four deliberate guard regressions were detected by assertions.
The separate JavaScript reference passed 30 cases.

All four saved real-validator states from Codex's return also passed through the
new HTTP client using a disclosed historical test clock. This is recorded-state
replay, NOT another validator run. The full package contains an optional
`run_devnet.py --protocol-version 3 --wallet-refresh` acceptance path, but this
new gate has not run against an engine. That runner change is not part of this
isolated add-on PR.

The complete package and the repository add-on are distinct artifacts. No full
repository suite is claimed for this add-on branch; its integration requires the
external native source above. Native state rules, identities and signature bytes
remain unchanged. Static validators, a trusted local clock/filesystem, a shared
journal and unpruned full-state receipts remain assumptions. No independent audit,
production custody, cross-device reservation, public deployment, real funds,
Actions, paid compute, DNS/site changes or Resident/Luna changes are claimed.
