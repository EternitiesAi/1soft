# Exact-candidate local validator acceptance

Continuation of PR #18 at `3a6723582af8d2fe25bc306cd1ac576449f68423`,
source tree `20075322cc09505b2581f39684c0a3b6064d04ac`.

This adds a real-engine acceptance path and its local tests. Authoring a path does
not mean it ran. Missing CometBFT or missing cached Go dependencies produces an
unassessed result, never synthetic consensus. The baseline's earlier validator
results do not qualify this candidate merely because it descends from them.
No monetary, native state, signature, wallet-reservation or snapshot-format rule
changes here. The existing explorer and archive runtime is reused unchanged.

## One candidate, one matrix

Run the local profile first from a clean checkout:

```sh
python tools/release/check_release.py --output ../new-local-results
```

With the genuine pinned CometBFT 0.38.25 binary and Go module dependencies already
available in an authorized local environment, supply the binary's independently
recorded SHA-256. The matrix does not download binaries or modules.

```sh
python tools/release/check_network.py \
  --cometbft /absolute/path/to/cometbft \
  --engine-sha256 EXPECTED_LOWERCASE_SHA256 \
  --output /private/new-network-results
```

The output must be new and outside the source checkout. The command verifies all
tracked source bytes/modes and five inventories, validates the exact executable
hash/version, then runs the official 15-field Go/Python snapshot-wire check in a
tracked-files-only copy. Only locally cached Go dependencies are allowed; proxy
fetching and automatic Go toolchain download are disabled. Ignored local wallet
files, environments and node homes are never copied into the probe checkout.

It then runs nine explicitly defined scenarios in isolated processes:

| Profile | Exercise |
|---|---|
| native-p1 | Existing protocol-1 four-validator regression |
| native-p2 | Existing protocol-2 account/key lifecycle regression |
| native-p3-flat | Existing shared-wallet delivery and receipt convergence |
| native-p3-smt | Same with sparse-Merkle commitments |
| retained-p1 | Four real applications keep two block-result rows; app/engine restart |
| product-p3-flat | Delivery, retention, live explorer reads, portable receipt archive |
| product-p3-smt | Same with sparse-Merkle receipt capsules |
| state-sync-p1 | Existing fresh fifth-node snapshot and post-snapshot payment gate |
| state-sync-p3-smt | Existing fifth-node snapshot/payment and compact-proof gate |

The last two use the unchanged state-sync runner and default local history. They
**do not** establish retention-enabled five-node state sync. The separate
final-Apply engine kill/restart window also remains outstanding. A green matrix
still sets `release_status=blocked`, `public_network_ready=false`, and
`real_funds_ready=false`. It is one-host acceptance, not independent operation.

Each runner result must match the current clean source commit/tree, runner bytes,
root inventory, binary hash, protocol and commitment mode. A top-level pass cannot
hide failed/missing checks. Product and retention profiles must contain their
specific evidence, not simply another large test count. Older result files are not
imported, and an existing output directory is refused. Incomplete process/log
capture cannot pass. The full source and binary are checked between scenarios.
Current timeout is 300 seconds per scenario, configurable from 60 to 1800 seconds;
this is a process bound, not a promised completion time or performance benchmark.

## Retention on actual node processes

`run_devnet.py --block-history-keep N` supports small acceptance windows 2 through
16, independently of the wider production-path CLI range. Every disposable node
application starts with that explicit policy. After the existing quorum
loss/restoration checks, validator 4's engine AND application are stopped and
reopened on their same databases, without supplying the retention flag again.
The persisted policy, contiguous current window, complete receipt count, and
resumed advancement must agree. The other three validators continue to provide
quorum. No chain database, key, signing history or app checkpoint is reset.

Comparing common-height block results needs to happen while they still exist.
For bounded-history mode only, the runner captures all four exact records together
with the chosen common state before later certificate/proof reads. If natural
advancement has already pruned a selected record, it selects a new common current
checkpoint within the existing bounded wait. It never treats unavailable metadata
as agreement or skips the actual equality and signed-root checks. The captured
records are retained in `retained-checkpoint-blocks.json`.

## Product path

The additional flag is deliberately explicit:

```sh
python scripts/run_devnet.py --cometbft /absolute/path/to/cometbft \
  --output /private/new-flat/run.json --protocol-version 3 \
  --decision-delivery --receipt-convergence \
  --block-history-keep 2 --product-journey
# Add --state-commitment smt-v1 for the second commitment mode.
```

The gate starts only after the genuine runner's validators are producing blocks.
It does not generate committee signatures itself. The existing CertifiedWallet
signs the two exact fixture payments against live signed state. Temporary vault
files are removed before delivery; the existing proxy drops the first downstream
HTTP reply only after verifying successful upstream CheckTx. Later receipt
verification, not CheckTx, establishes execution.

The explorer initially imports the wallet's already authenticated signed checkpoint
under the locally selected genesis. It then runs its existing read-only RPC
collector against the live node. The archive packs and independently verifies each
exact delivery receipt and the signed ancestry from inclusion to its state anchor.
Neither component is given a wallet-writing API or a private key. The runner
compares the wallet's logical journal before/after the read-only operations.

The five required states are:

| Stage | Shared wallet pending | Explorer recorded budget spend |
|---|---:|---:|
| Both payments signed | 100 | 0 |
| Raven receipt archived/indexed | 100 | 60 |
| Raven wallet reconciliation | 40 | 60 |
| Atlas receipt archived/indexed | 40 | 100 |
| Atlas wallet reconciliation | 0 | 100 |

The explorer must retain the exact native execution receipt and verified original
block inclusion for both payments. Each derived database is actually closed and
reopened. After source-local block-result pruning, the old node query must explicitly
say `pruned_local_block_results`, not payment absence. The archived capsules still
verify and the explorer still retains their exact body evidence. The existing
runner separately checks exactly one forwarded submission per original payment
and older-receipt convergence without wallet, transport or RPC changes.

Observations, original signed transaction bytes, full receipt packets, capsules,
per-stage explorer views and source evidence, and a final self-contained explorer
HTML are retained under `product-evidence/`. These are PUBLIC chain records, not
private keys, but can still be sensitive usage data and should remain in the private
operator evidence directory. Each refresh return/error type is saved before the
next assertion. A failed write/report never proves that wallet or node state rolled
back. The overall result and exact partial observations remain distinct.

## Local tests are not engine runs

The helper tests exercise actual native state, SQLite, encrypted disposable
signing, loopback HTTP reply loss, explorer collection, receipt archival and
pruning. Their committee headers are explicitly synthetic fixtures. Separate unit
checks use synthetic runner reports to test the matrix's rejection rules; those
reports are never accepted as evidence that CometBFT ran.

The archive's standalone verifier now pins the SAME 26 runtime/dependency/helper
entries rather than the unrelated whole root inventory digest. All previous file
byte pins remain intact; updating an acceptance runner no longer prevents testing
an unchanged archive. This is a verifier-composability change, not relaxed receipt
verification. The central release command still checks every tracked source file.

Independent hosts, final-Apply crash qualification, state-history redesign,
validator-set evolution, custody, economic/genesis decisions, external security
review and public readiness remain separate. No Actions, paid compute, public
services, DNS/site work, Resident/Luna/Psyche changes, production keys, real funds,
force pushes or merges are performed by these commands.

Primary API basis: CometBFT v0.38.25, `spec/abci/abci++_methods.md` and
`proto/tendermint/abci/types.proto`. AppHash from execution at H is authenticated by
header H+1; CheckTx admission does not establish committed execution. The exact
existing 1soft verifiers enforce that distinction.
