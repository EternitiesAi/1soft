# 1soft private network explorer

The approved visual design and interactive application from the private Sites
deployment, preserved without redesign. Read-only views link blocks, native
transfers and addresses; the network view shows source provenance and explicit
unavailable live telemetry. All ledger records are synthetic fixtures.

Private owner-only deployment:
https://onesoft-network-explorer.xnuonux.chatgpt.site

## Use and check

Requires Node 18 or later for the dependency-free checks:

```sh
cd tools/private-network-explorer
node --test tests/*.test.mjs
```

For a local preview, serve `dist/` on a literal loopback address:

```sh
python3 -m http.server 8080 --bind 127.0.0.1 --directory dist
```

Open `http://127.0.0.1:8080/`. Hash routes support direct block, transaction and
address links. Search accepts a block height, transaction hash, account label or
address; lists support filtering and pagination. Live mode explicitly displays
unavailable state and does not silently substitute fixtures.

## Design and data boundaries

The graphite sidebar, soft neutral canvas, white ledger panels, warm orange
accents, responsive navigation, SVG icons and typography are preserved in the
exact deployed assets. They use no external fonts, images, analytics or RPC.
Amounts stay integer atomic-unit strings, with no decimal scale or fiat price.
Recorded balances exclude pending wallet holds and establish no spending authority.
Fixture grants are labels, not claims that a live agent performed work.

The fixture uses the native `lab_` address convention and `system:fees` account.
Its block, transaction, wire and receipt hashes identify synthetic display records;
they are not original signed evidence or verified consensus outputs.

## Source lineage

Copied from Sites source commit
`7a152a3d37fb0977fe6c244f18c9d6eefb3aa3f3`.
The original site's repository evidence remains pinned to
`EternitiesAi/1soft@19842665496ac677b5f6f78b7c3dd7a06baa16fd`.
This newer import does not rewrite that source snapshot or transfer current
qualification to earlier evidence. Exact file hashes are in `SOURCE_PROVENANCE.json`.

Read for the original display boundary: README.md, AGENTS.md,
docs/PROTOCOL4_DEVELOPMENT.md, docs/COIN_IDENTITY.md, docs/DURABLE_ALPHA.md,
docs/LOCAL_BLOCK_HISTORY.md, tools/protocol4-explorer/README.md, that explorer's
projection/web sources and projection tests, and src/native_core.py lines 1–140.
The P4 explorer's own source/README governs its current historical display boundary;
older documents may describe earlier feature scope.

## Verification and deployment

All 13 functional checks pass, including linked-record consistency, integer
accounting, routes/search/filter/pagination, event handlers, mode switching,
copy failures and unavailable fixture loading. The minimal DOM harness executes
production handlers but does not establish browser rendering or consensus.
Browser rendering remains unverified because the required browser-control skill
was unavailable. Native, engine, full-repository and independent security checks
were not run for this static-only import.

This directory is separate from the existing verified P4 explorer. No application,
wallet, validator, monetary format, root source manifest or Actions file is modified.
It does not serve a live RPC proxy, sign, submit payments or ingest proofs.

The existing private Site remains deployed from its own Sites source repository.
Its `.openai/hosting.json` is intentionally excluded from this import: copying a
Site identity into the cryptocurrency checkout would not establish source binding
or authorization to redeploy it. This import performs no publication, access change,
DNS change or production infrastructure action. Keep hosting private; connecting a
live source or publishing publicly requires a separate explicit approval.
