# Native invoice commitments implementation plan

> **For agentic workers:** Use `dispatching-parallel-agents` for independent reviews
> or `executing-plans` for inline tasks. Parent owns all coding in this continuation.

**Goal:** Authenticate the exact approved invoice terms in the original native
payment signature and verify them at merchant enrollment and delivery.

**Architecture:** Explicit fresh-genesis P4 capability; a domain-separated public
terms commitment in the existing signed transfer operation. A distinct wallet
review carries its preimage and rechecks expiry after unlock. Existing journals,
plain transfers and historical version behavior remain intact.

**Tech Stack:** Existing Python, SQLite, cryptography Ed25519 and pinned CometBFT
0.38.25; no new dependency or acquired code.

**Spec:** `docs/NATIVE_INVOICE_COMMITMENTS.md`.

## Global constraints

- Preserve previous refs, workspaces, keys, journals, evidence and ZIPs.
- No Actions, paid/public compute, deployment/DNS/site/other-project changes,
  real funds, production keys, force push or remote merge.
- Existing protocol and plain-transfer behavior must remain unchanged.
- Exact candidate source, intentionally changed files and raw failed execution
  must be recorded; no historical 445-byte seal claim for modified native code.

## Task 1: Native capability and commitment contract

Files: new `src/invoice_terms.py`, new `tests/test_invoice_commitments.py`, scoped
changes `src/native_core.py` and `tools/protocol4-wallet/src/p4_wallet.py`.

Interfaces: `terms_checked(value, genesis_sha256, recipient, units, now_ns=None)`
returns canonical validated terms; `terms_commitment(value)` returns a 64-hex
digest. `P4Wallet.prepare(..., invoice_terms=None)` retains plain behavior when
absent and signs the committed preimage only under the explicit capability.

- [ ] Write a real-ledger acceptance test that a fresh capable P4 ledger executes
  an owner and delegated transfer carrying the commitment.
- [ ] Run it against old code and retain the expected genesis rejection.
- [ ] Add strict fresh-genesis and exact transfer-field validation; reject flags
  on other versions, booleans/unknown versions, malformed hashes and unknown fields.
- [ ] Add signature/commitment substitution, receipt restore and budget/nonce tests.
- [ ] Add wallet preimage review, historical reconstruction and before/after-unlock
  expiry enforcement. Test advancing clock with zero decisions and zero holds.
- [ ] Run focused old and new native/wallet tests; retain results.

## Task 2: Invoice caller and merchant proof integration

Files: `tools/local-platform/src/payment_requests.py`, `platform_service.py`,
`tools/private-payments/src/payment_x402.py`, `private_payment_desk.py`,
`merchant_book.py`, `merchant_ops.py`, `merchant_devnet.py`, network CLI and tests.

Interfaces: new offer v2 includes `resourceSha256`; canonical derived full terms
are passed to the original wallet, and the merchant checks their signed commitment.
Old v1 offers and workspaces retain their prior paths.

- [ ] Write term substitution and expiry regressions before caller changes.
- [ ] Derive exact terms from immutable quote and independently selected pins.
- [ ] Require resource digest equality at quote retention, enrollment and proof
  replay; reject a missing/mismatching native commitment before delivery.
- [ ] Reconstruct approval from original retained terms and bind the request.
- [ ] Add an explicit fresh initializer capability switch; never repin an existing
  configuration, genesis, readiness marker, policy or key.
- [ ] Run affected old and new component tests.

## Task 3: Exact-source validator qualification and delivery

Files: feature-specific runner/qualification, selected manifest pins and final docs.

- [ ] Create bounded tests for qualification success/failure/provenance predicates.
- [ ] Record exact parent a09afbf membership and every intentional source change;
  preserve historical immutable qualifiers and all old test methods.
- [ ] Freeze clean candidate before full qualification; verify unchanged afterward.
- [ ] Run all original component suites and affected actual validator gates using
  the pinned engine, followed by the new signed invoice journey and cold recovery.
- [ ] Inspect returned source/proof reviews, repair real failures, retain negatives.
- [ ] Publish an authorized normal draft stacked on PR35, preserving the ref-only
  Windows publication checkout/index state; no merge or Actions.
- [ ] Return one exact-source ZIP, sanitized raw logs, CODEX_RESULT.md/json and an
  independently read-back archive receipt with explicit unassessed boundaries.
