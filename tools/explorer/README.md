# 1soft Explorer — verified development read model

A browser explorer and persistent, read-only-chain index on the existing 1soft
native protocol. Parent: PR #16 at `3d4a11f90b540d195d8c0e40b341434333f8110d`,
tree `6fa6525e73f8ea12a211c5cefd7619c2b739eec4`.

This is product infrastructure, not the marketing website or a second wallet.
Native/ABCI/state-sync/signing/reservation code and the root inventory are unchanged.
No operator-kit retry, PR #11 merge, public endpoint, paid compute, Actions, real
funds, DNS/site change, Resident/Luna work or custody claim is included.

## What works

The explorer shows an overview, indexed blocks, recorded transactions, account
activity, protocol-3 budgets/grants and the pinned static validator set. Search,
pagination and detail inspectors work on desktop and mobile. Amounts remain exact
decimal strings, formatted with JavaScript BigInt; there are no invented decimals,
market values, token prices, yield, exchange listings or circulating-supply claims.
Fees are still in the native system fee account, not silently described as burned.

A stored index is populated only after the existing verifier authenticates the full
native state against its signed H+1 header, verifies each supplied signed header,
checks consecutive full previous-block IDs/timestamps, validates native receipt
signatures/invariants, and verifies supplied block bodies against their data roots.
When a body's height has recorded receipts, those exact signed bytes must occur in
that body. Each reader revalidates the evidence and rebuilds/compares the materialized
view: rehashing an altered balance field in the view does not make it trustworthy.

Every first import requires an independently chosen engine-genesis file digest AND
final signed-header hash. Subsequent imports extend the stored history rather than
resetting it. Historical receipts already recorded must remain byte-identical.
Same-height conflicting headers or changed block bodies are refused. Different
valid quorum-signature subsets for the *same block* are accepted without falsely
calling them a fork; the existing certificate is preserved. An index never decides
which of two genuinely conflicting blocks should win.

## History is not a live balance

The UI explicitly identifies synthetic fixtures or unattributed development
evidence. Cryptographic verification does not prove that validators were on separate
machines or that an imported certificate came from a live process. Even a recent
local RPC result does not guarantee globally latest state.

An H+1 signed header authenticates state H. H+1 is not displayed as an executed
block. Block bodies may be unavailable while receipts remain in the authenticated
state. A missing body is not an empty block; a missing indexed block or transaction
is not proof of nonexecution. Receipts get a separate inclusion badge only when the
corresponding block body was verified. Failed or rejected attempts absent from
native receipt history are not fabricated as failed transactions.

Balances exclude pending signed wallet obligations. Budget and grant values describe
on-chain state at the indexed height; they do not authorize another spend. Validator
participation describes the chosen signed anchor, not online status or uptime.
Browser HTML is presentation, not a separately signed proof or a browser light
client. The Python verifier authenticates the source evidence. Exported HTML can be
edited and must not substitute for verifying the supplied evidence and trust pins.

## Storage and bounded operation

An explorer database is distinct from node, wallet, dispatcher and receipt archive
files. Explicit creation is exclusive; unknown/empty/existing databases are not
initialized or repaired. Private owned POSIX directories/files, no symlink or
hard-linked database/sidecars, a unique SQLite application ID and exact table names
are required. Successful imports atomically replace the evidence and projection in
one WAL transaction. Readers get a consistent snapshot. Duplicate imports are
idempotent; a failed import leaves the last verified snapshot unchanged. Process
crash tests cover immediately before and after database commit.

This is a bounded development index, not a production-scale relational indexer:
at most 20,000 native rows, 65 signed headers per input, 4,096 retained signed
headers, 16 MiB per input and 32 MiB each for retained evidence and derived view.
Capacity exhaustion refuses updates without eviction. Full receipt/state witnesses
and revalidation still cost CPU/RAM; no throughput or total-disk bound is claimed.
Separate pagination in the browser is presentation, not server-side query scaling.

## Run on the published parent and this add-on

Use the repository's existing pinned dependencies; no automatic dependency download.
From the repository root:

```sh
python tools/explorer/tools/verify.py --native-root .
export PYTHONPATH="$PWD/src:$PWD/tests"

# Reproducible preview: real native execution, synthetic committee signatures.
python tools/explorer/scripts/demo.py --output /private/new-demo
# Open /private/new-demo/explorer.html directly, or serve its index with the CLI.
```

`demo` writes fixture genesis, source evidence, a derived JSON view, the explorer
HTML, and a separate development index. It never writes private-key files. Its
public deterministic test seeds must never hold value.

For an existing local testnet, start with independently pinned genesis and a
separately chosen header hash. Do not let an untrusted node supply both evidence
and its own trust. The plan does not create validators, keys or a public network.

```sh
python tools/explorer/scripts/explorer.py \
  --genesis /private/engine-genesis.json --genesis-sha256 EXPECTED_GENESIS_DIGEST \
  --index /private/explorer.sqlite init

python tools/explorer/scripts/explorer.py \
  --genesis /private/engine-genesis.json --genesis-sha256 EXPECTED_GENESIS_DIGEST \
  --index /private/explorer.sqlite sync \
  --endpoint http://127.0.0.1:26657/ --initial-header-hash EXPECTED_HEADER_HASH

python tools/explorer/scripts/explorer.py \
  --genesis /private/engine-genesis.json --genesis-sha256 EXPECTED_GENESIS_DIGEST \
  --index /private/explorer.sqlite serve --port 8787
```

`sync` is an explicit finite read operation. It captures `/state` once, retries only
that state's fixed H+1 commitment up to four times, and collects a bounded consecutive
header/body window. It reuses the parent strict read-only HTTP reader: only
`abci_query`, `commit` and `block`, literal `127.0.0.1`, no DNS, redirects or proxies.
It permits at most 133 requests and a 45-second child-process deadline. It requires
the final header to be within 300 seconds of the trusted local clock (up to 30 seconds
of future skew). This freshness check does not create spending authority. Failed
reads or an oversized gap leave the index unchanged. No periodic polling is created.

For a gap exceeding the input window, supply authenticated consecutive intermediate
snapshots through `import`; do not reset the index or silently skip ancestry.
`import --evidence FILE --initial-header-hash HASH` also supports offline historical
evidence. Omit the initial pin after the first import unless explicitly checking
another expected header. A supplied pin is always checked.

The evidence envelope is exactly `schema, state, state_commit, headers, blocks`.
Headers form a consecutive list ending at `state_commit`; blocks are a unique
subset of those headers at or below the state height. Unauthenticated extra RPC
block fields are discarded. `inspect` prints summary data; `export --output NEW.html`
creates a portable, self-contained snapshot without remote assets or fonts.

The loopback viewer exposes only `/`, `/api/view`, and `/api/evidence` via GET.
It rejects cross-origin/wrong-host requests, unknown paths and all write methods.
No source endpoint or file path can be chosen through the browser. The browser's
Reload button reads the separately updated local index; it does not call a node.
The single-thread development HTTP server has connection timeouts and no public
binding option. It is not a hardened Internet service or production operator UI.

## Acceptance still required

Before claiming a live explorer integration, run this exact add-on against the
pinned real CometBFT testnet, then interrupt/reopen it and compare its rendered
records with the signed native evidence. Existing engine results belong to their
own source revisions. The local HTTP tests use synthetic committee fixtures;
importing previously captured real-validator certificates is an offline replay,
not another live validator run.

See VERIFICATION.md and TESTNET_RELEASE_SCOPE.md. This component makes the chain
inspectable; it does not complete protocol upgrades, state pruning, custody,
independent operators, economics or mainnet qualification.
