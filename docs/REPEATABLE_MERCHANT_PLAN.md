# Repeatable local merchant payments implementation plan

> For agentic workers: use `dispatching-parallel-agents` for the independent
> network and merchant tasks; use `executing-plans` for their integration.

**Goal:** Run multiple separately approved native DEV invoice payments through
one intact merchant book and a real local operator interface, without changing
P4 monetary, signature, budget, reservation or delivery semantics.

**Architecture:** A fresh version-2 development workspace preallocates a finite
pool of 2–16 zero-balance merchant accounts. Each quote permanently consumes one
recipient assignment. The original P4 wallet remains the sole financial journal.
The merchant verifies independently enrolled exact wires and native execution;
static loopback routes return only their retained public resources.

**Tech stack:** Existing Python 3.14.4 environment, cryptography 46.0.4, SQLite,
CometBFT 0.38.25 and original P4 modules. No new dependency or acquired SDK.

**Spec:** This document and `PRIVATE_PAYMENTS_FOUNDATION.md`; architecture and
privacy limits remain those in `PRIVATE_PAYMENTS_ARCHITECTURE.md`.

## Global constraints and acceptance

- Start at frozen `e6f36c2b1d7912ba48ea35cd02c9166548a9c839`; preserve all 445
  original parent files at `d14165df5476a617bb3048e61bb80b9767722eac` byte for byte.
- Preserve prior source, runtime homes, journals, keys, evidence and ZIPs. New
  workspace creation requires a nonexistent outside-source private Linux path.
- No Actions, paid/public compute, public deployment, DNS/site changes, other
  projects, real funds, production keys, force push or remote merge.
- No payment-key sidecar signer, account-ID commitment trick, quote commitment
  through unsigned request notes, consensus change or claimed shielded ledger.
- Original exact wire, financial decision and one submission attempt remain
  durable. HTTP success, receipt retention and restart never retire a hold.
- Source and engine pins, complete successful test membership, actual validators,
  execution provenance and exact owned cleanup are required for qualification.
- Every new recipient is a development genesis account; finite pool exhaustion
  fails closed. No recipient reuse, genesis rewrite, account-opening signer or
  live migration is added. Copied books/devices remain outside the guarantee.
- Native signatures still do not authenticate resource or invoice terms. Quote
  pins and independent enrollment remain mandatory. Full ledger capsules public.

## Task 1: Fresh finite recipient workspace

Files: new `tools/private-payments/src/merchant_devnet.py`,
`scripts/1soft_merchant_network.py` and their focused tests; minimal private payer
CLI dispatch change in `scripts/1soft_private.py`. Original local-platform files
remain unchanged.

Interfaces:

```python
initialize(workspace, engine, *, password, recipient_count=3) -> dict
load_configuration(workspace) -> dict
MerchantNetwork(workspace, engine, *, clock=time.time_ns)
network_for_workspace(workspace, engine, *, clock=time.time_ns)
```

`MerchantNetwork` supplies `root`, `config`, `clock`, `ready()`, `policy()` and
`service()` like LocalNetwork. Config uses schema 2 and
`1soft/local-development-workspace/v2`, retains `merchant` as first recipient and
adds ordered `merchant_recipients`. READY uses schema 2 and
`1soft/local-development-ready/v2`, pinning original config and policy hashes.
`development-keys.json` contains only public keys. Every encrypted vault, public
key, genesis allocation, validator configuration and immutable file is checked.
Owner allocation stays 1000 DEV, recipient allocations zero, fee stays 2.

- [ ] Observe expected-red tests for a three-recipient workspace, strict v1/v2
  dispatch, altered pool/key/genesis rejection and refusing existing paths.
- [ ] Implement the fresh initializer and exact loader. Bootstrap retains the
  original three setup operations with all pool recipients in the shared budget
  and both grant allowlists. No canonical financial journal exists before setup.
- [ ] Verify an existing setup wire with the pinned public key; never re-sign or
  resend it. Ready restart is key-free and retains original policy.
- [ ] Implement TTY-only init/run commands and source-dispatched payer CLI.
  Secrets never enter arguments, environment, logs or JSON metadata. Runtime
  ownership and lifetime are bounded; partial setup is retained and refused.

## Task 2: Merchant operations and static multi-route HTTP

Files: new `src/merchant_ops.py`, `scripts/1soft_merchant.py`, focused tests and
minimal private `src/merchant_http.py` extension. Parent files stay unchanged.

```python
MerchantOps(network).init_book()
MerchantOps(network).add_quote(recipient_index=..., merchant_origin=...,
    resource_path=..., amount_units=..., resource=..., expires_ns=...,
    description='', mime_type='application/octet-stream')
MerchantOps(network).inspect()
MerchantOps(network).export_quote(quote_id, required_out=..., expectation_out=...)
MerchantOps(network).enroll_wire(quote_id, payer=..., wire=..., evidence=...)
MerchantOps(network).serve(quote_ids, session_file=..., seconds=..., port=None)
```

The exact validated ready network supplies genesis and policy. The sole merchant
book is `workspace/merchant.sqlite`; HTTP clients cannot choose another book.
Explicit recipient indices select only pinned pool members. Published quote
assignment is immutable even if output fails; export retrieves original bytes.
Resource bytes are bounded and explicitly public. Enrollment accepts only an
operator-selected original wire and independently verified evidence.

- [ ] Observe expected-red tests for multiple exact routes, route swapping,
  duplicate/ambiguous route configuration, pool exhaustion and assignment reuse.
- [ ] Implement key-free operator commands with exclusive private output files.
  No signer, payment dispatch, implicit enrollment or hold retirement endpoint.
- [ ] Preserve `server(..., quote_id=...)` and `configure_quote` behavior; add
  atomic one-time `configure_quotes(tuple)` for distinct paths at one origin.
  Each synchronous handler validates its selected original book/quote/resource.
- [ ] Serve literal loopback only, one fresh private session token, a fixed route
  map and bounded lifetime. Every repeated POST replays actual native proof.

## Task 3: Real multi-invoice journey and complete qualification

Root owns new `src/merchant_acceptance.py`,
`scripts/run_merchant_acceptance.py`, `scripts/qualify_merchant.py`, qualifier
tests, source inventories and delivery records.

- [ ] Define exact named checks and report predicates before implementation.
  Reject malformed, partial, exploratory, mismatched-source/run/engine and
  incomplete-cleanup reports with focused negative tests.
- [ ] Create a fresh three-recipient runtime using the real network CLI. Own four
  actual validators. Exercise real merchant CLI init/quote/export/enrollment and
  payer CLI approval/recovery on three independent invoices and recipients.
- [ ] Pay through owner and both delegated roles. Reuse the one financial journal;
  verify overlapping budget accounting, fees, supply and retained original wires.
- [ ] Reject proof/route/quote substitution; abandon a real HTTP response after
  durable fulfillment. Preserve holds through receipt retention and cold restart.
  Explicit native reconciliation alone retires the original obligations.
- [ ] Preserve keys/ciphertexts/config/policy/quote assignments/fulfillments across
  restart without new signatures or dispatch. Refuse a fourth quote in the pool.
- [ ] Commit candidate and regenerate only private package inventory. Run the
  complete inherited + private qualification on that exact clean source, then
  new merchant actual qualification. No earlier exploratory result substitutes.
- [ ] Independently review source/evidence; fix failures without weaker checks.
  Publish a normal draft branch stacked on PR34 under existing authorization.
  Return one exact source/patch/sanitized-log/result ZIP and audit its readback.

## Completion boundary

Completion means the multi-invoice local flow, complete exact-source tests,
actual validator journey, cleanup, review and concrete source/evidence return
work. It does not mean native invoice commitments, unlimited billing, private
ledger proofs, production custody, independent operators, external review,
commercial demand, investment returns, public deployment or a real-money launch.
