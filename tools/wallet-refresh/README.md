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
requests one state query, up to four attempts for its fixed next signed
commitment, and up to four batches of at most 64 headers. The client never
chases a newer state during those retries. The default is two batches. Collection
jobs have a 15-second process deadline, header
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

Both source inventories are checked first. Ten isolated add-on integration tests
passed against the complete local catch-up core, including transient and permanent
failure of the captured commitment. For the CLI, set `PYTHONPATH` to the
returned source's `src` directory before calling `scripts/refresh_wallet.py --help`
inside this add-on. Genesis, policy, journal and endpoint are explicit inputs. No
password, vault or broadcast option exists.

## Evidence scope

The earlier integrated conversation package passed 1,061 Python cases and
recorded-state replay, but its optional engine acceptance gate was unexecuted.
Codex applied that package to the exact local catch-up tree, then ran the new
`run_devnet.py --protocol-version 3 --wallet-refresh` gate against actual pinned
CometBFT v0.38.25 processes. The first flat-state attempt failed at the refresh
assertion after the manual 130-header catch-up. Its runner did not retain the
client's partial result, so the exact status from that attempt is unknown.
Inspection revealed a timing race between the state query and its next signed
commitment. After the bounded fixed-height retry repair, the flat-state scenario
passed 61/61 checks and compact SMT passed 66/66. Both runs exercised the
64-header partial refresh, preserved holds, reopened the wallet, collected the
remaining four headers, and reconciled the full state without signing or
broadcasting through this client.

The final complete local source passed 1,062/1,062 Python cases with zero skips,
failures or errors, 30/30 JavaScript reference tests, and 110/110 required-source
checks. The real-validator runner repair, integrated package source manifest,
and full catch-up core remain outside this isolated add-on PR. Raw network and
test logs are in Codex's separate return ZIP.

The complete package and the repository add-on are distinct artifacts. No full
repository suite is claimed for this add-on branch; its integration requires the
external native source above. Native state rules, identities and signature bytes
remain unchanged. Static validators, a trusted local clock/filesystem, a shared
journal and unpruned full-state receipts remain assumptions. No independent audit,
production custody, cross-device reservation, public deployment, real funds,
Actions, paid compute, DNS/site changes or Resident/Luna changes are claimed.

## Durable diagnostic records (optional follow-up)

Add `--report-dir /absolute/path/to/a-new-run-directory` to the refresh CLI,
or call `recorded_refresh` from `refresh_trace`. Outcome, phase and bounded counts
are flushed before control returns to a caller's assertion or terminal output.
An interrupted record is not a failed payment, completed sync or rollback claim.
No balances, account identifiers, keys, signatures or response bodies are recorded.
Use `scripts/inspect_refresh.py DIRECTORY` for offline inspection without the
native dependency. This inspector reports log completeness, NOT wallet freshness.
See `DIAGNOSTICS.md` for limits, exact source/evidence distinctions and tests.
