# 1soft continuation handoff — v0.12

Owner direction: a genuine independent native Layer 1 and human/agent financial
account product. No GitHub Actions, paid resources, customer funds, public issuance
or DNS edits. 1soft.org/Cloudflare setup is a separate owner/Codex lane. Branding,
public supply, price, allocation and issuer/card relationships remain open.

Read NATIVE_BUDGETS.md and VERIFICATION.md first. This checkpoint deliberately adds
opt-in native protocol 3 using a fresh genesis; it does not migrate protocol 1/2.
The previous handoff's instruction to keep 1/2 unchanged is retained through
version separation and golden-replay tests, not through a silent version upgrade.

New src/native_budgets.py implements owner-scoped immutable lifetime budgets.
All v3 grants bind exactly once to a budget. Each successful delegated payment
and its native fee charges both the individual grant and the shared aggregate,
with balances/nonces/receipts in one atomic native transaction. Every budget.spent
reconciles to linked grants. Caps can overlap; unused grant caps are not reserved
shares. Owner-signed spending is outside these agent caps. No automatic reset,
card/crypto joint limit, escrow or new coin balance is created.

src/native_core.py, block_application.py, commit_verifier.py, offline_signer.py
and the LOCAL certified_wallet.py are integrated. Snapshot tables and commitments
are version-aware; the wallet shows both remainders and checks before unlock.
scripts/budget_network_case.py supplies the actual-engine scenario. run_devnet.py
accepts explicit 3; local_dev.py retains real tests for 1/2/3. The remote wallet_state.py
is different and was not modified or tested as a full remote checkout.

623 Python cases passed across 16 reconciled batches, with 54 new (36 rules + 18
integration); separate JS reference 30 passed. Four deliberately weakened controls
produced assertion failures. Actual process-crash application tests passed, but
all signed committee certificates are synthetic. Do not call application testing
real distributed consensus. The official engine is still absent; normal module
DNS failed and the real-network gate returned unassessed with zero engine steps.

Parent local commit: 5756dbae1854fb09ec06a7c918c9e6bf38979a09.
Observed main: 941c6241d89761f2074c121af29539c354f6cdcd.
Observed PR2 head: 29705061c3cbb8b09ac18001c2b980d3183215a1 (open/unmerged).
Recheck actual refs before future writes. RELEASE.json records this local commit
once packaged; never force-replace the owner's separate remote history.

PUBLICATION: the helper-only tree 1f27fc17898d9f0c422010d4befe5b1ee4052c9a exists
without a ref. The following native-core integration tree write was blocked by
an indeterminate platform safety check. No v0.12 commit/ref was published. Do not
retry blocked native-core, ABCI transport or payment-jobs source through encoding,
fragments or another tool. A status comment may describe the outcome, not publish
the blocked code. The full local package remains the delivery artifact.

Required full source inventory: 69 files. Do not shorten the inventory to make an
incomplete remote node green. No active Actions workflow exists. Local core mode
still exercises the legacy 90-case subset; it does not cover the new budgets.
Use both new test modules or the complete suite for protocol 3. Preserve failing
logs and exact test coverage. Do not equate increased test counts with consensus.

Next decisive integration: obtain the official pinned engine through supported
local tooling; run upstream codec plus genuine four-validator 1/2/3 scenarios,
including transfers, receipts, aggregate budgets and quorum failure/recovery.
Do not write replacement consensus to claim completion. After that, prioritize
bounded authenticated state, operator/key security, source-lineage reconciliation
and measured public-testnet requirements, before live funds or financial services.
