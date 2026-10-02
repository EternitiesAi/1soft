# 1soft local release qualification

**Base:** PR #17, `79d939f16adc04617d5f573ced2d27dab08146e3`, tree
`5e8b9215c927d30d4d3ba0c177fd4f874d1f0f14`.

This introduces one local release-check command and two complete cross-component
journeys. It does not change any native, wallet, delivery, archive or explorer
implementation. It neither merges existing PRs nor declares a release ready.

## One checkout, one run, explicit result

With the pinned Python dependencies, Node and Git already installed, from a clean
POSIX checkout:

```sh
python tools/release/check_release.py --output /private/new-release-evidence
```

The output directory must be new and outside the checkout. This command does not
download dependencies, run GitHub Actions, start CometBFT, access public endpoints,
provision hosts, sign releases or perform financial operations. Tests use temporary
local files, deterministic disposable fixture keys and loopback HTTP. Never use
fixture keys/genesis for value. The 300-second default deadline is per group, not
a performance commitment; `--timeout` accepts 30 through 1800 seconds.

Before running, the command compares EVERY tracked file and executable mode with
HEAD, refuses untracked/edited source, records the exact commit/tree and per-file
SHA-256s, checks the root and four add-on manifests, and checks installed Python
dependency versions against requirements.txt. It rechecks the full source before
each Python group and after all checks. Shallow Git history is supported; full
ancestry is not required to verify the checked-out tree. Git identities and hashes
are custody checks, not an independent audit, signed release or hostile-host trust.

The native suite, account view, decision delivery, receipt archive, explorer and
new release tests run in separate Python interpreters. This prevents same-named
`test_cli.py` modules in unrelated add-ons from replacing one another in discovery.
The runner reconciles all discovered and successful IDs. Empty suites, duplicate
IDs, failures, errors, skips, expected failures and unexpected successes cannot
produce a local pass. Each report binds its group, source fingerprint and unique
run ID. An old report from another revision or run cannot be added to the total.
The JavaScript reference runs separately and must report no failed, skipped,
cancelled or todo cases.

Each child has a process deadline; only the process group it spawned is cleaned
up. Logs are capped at 8 MiB each, with truncation identified and refused for a
passing result. All results/logs remain separate and content-hashed. A failed or
interrupted group is not counted as successful. `started.json` without a final
`result.json` means incomplete, not passed. Reusing an existing evidence directory
is refused. These are developer-owned test processes on a trusted host, not a
sandbox for hostile arbitrary code. The interpreter, OS and toolchain are recorded
but are not independently attested or proven reproducible by this tool.

## Profile contents and exclusions

The account profile selects `test_account_view.py`. Its optional
`test_account_catchup.py` depends on unpublished `wallet_catchup.py` and is explicitly
outside this profile. This is not a skipped test reported as passing. The release
report records that exclusion. Browser rendering and real-engine/independent-host
acceptance also remain separate. The profile does not import the divergent PR #11,
PR #13, partial operator kit or an older local source ZIP.

A local pass produces **`local_checks: passed` AND `release_status: blocked`**.
Exit zero means only that this local profile passed. `public_network_ready`,
`real_funds_ready`, and `consensus_executed` remain false. Exact-candidate engine,
state-sync, final-Apply crash, independent-host, security/custody and economics
checks remain explicitly unassessed. Prior validator reports never satisfy them
merely because the source descends from the old revision.

## Integrated journeys, not counts accumulated from historical PRs

The new flat and SMT journeys share one existing CertifiedWallet signing journal.
Raven signs 58 + 2 fee and Atlas's 39 + 2 is refused; 38 + 2 fits. Both fixture vault
files and the other fixture vaults are removed before delivery. Each original
payment is submitted once to the existing local fixture server, which executes
native state and actually drops its TCP reply. The client reopens and collects its
exact receipt without resending.

The explorer and receipt archive are then updated before wallet reconciliation:

| Point | Wallet pending | Explorer recorded budget spent |
|---|---:|---:|
| Both payments signed | 100 | 0 |
| Raven receipt archived/indexed | 100 | 60 |
| Raven wallet reconciliation | 40 | 60 |
| Atlas receipt archived/indexed | 40 | 100 |
| Atlas wallet reconciliation | 0 | 100 |

The difference is intentional: an explorer or archived receipt never owns the
wallet's reservation. Reopening the index/archive preserves the records. Revisiting
Raven's older receipt returns already_recorded without releasing anything twice.
Old local block-result rows are pruned while the six native receipts remain.
A fresh application restores the source snapshot at height6, rejects the original
payment as replay, and follows one subsequent empty block to height7. Both source
and target states match and the marker stays at height6. Finally the source closes
and both archived receipts are exported and verified offline.

Committee signatures, RPC responses and keys come from existing synthetic fixtures.
This exercises actual native execution, encrypted fixture signing, SQLite, HTTP
and component APIs; it is NOT actual validator consensus, the CometBFT state-sync
network, a new production wallet, cross-device coordination, or public readiness.
The journey's output is retained in the release-group log as INTEGRATED_JOURNEY
JSON. Code changes to this test do not alter existing production-path semantics.

## Next exact-source acceptance

Before calling the combined candidate engine-qualified, run the pinned official-Go
wire test, P1/P2/P3 flat+SMT validator regressions, and the current state-sync runner.
Then explicitly test retention-enabled application processes and the explorer /
receipt-archive journey against real validator output. The inherited run_devnet
currently has no retention flag; its default run does not test retention-enabled
operation. Add and test that option rather than infer coverage. Retain exact source,
binary hashes and raw failures; do not soften assertions or replace the engine.

An actual engine final-Apply kill/restart still requires its own acceptance test.
Independent hosts, public networking, production key handling, new native history
formats and public economics remain outside this local milestone. No deployment,
Actions, paid compute, DNS/site changes, Resident/Luna/Psyche work, real funds,
force-pushes or merges are authorized by this command.
