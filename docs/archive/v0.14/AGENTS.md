# 1soft engineering contract — v0.12

Dom selected private xnuonux/1soft for a genuine independent native Layer 1 and
persistent-agent financial account. Preserve owner history, placeholder, private
visibility and parallel work. Domain 1soft.org setup is a separate Codex lane.

Read docs/HANDOFF.md, docs/VERIFICATION.md and docs/NATIVE_BUDGETS.md first.
No GitHub Actions, self-hosted Actions, paid compute, DNS edits, public deployment,
production keys, customer funds or issuance without explicit authorization.

Protocol 3 is opt-in on a fresh development genesis. Do not silently migrate
protocol 1/2, rewrite histories, recycle spending counters or invent public supply
or dollar backing. Retain legacy golden vectors unchanged. Shared budgets are
permission ceilings, not escrow or cross-rail custody. Owner transfers are not
agent-budget debits. Grants cannot administer their parent budgets.

Full local source has 69 required files and 623 discovered Python cases. Core mode
still selects the legacy 90 cases. The 54 budget cases are included in 623. Do not
shorten manifests or add subset counts together. Preserve failures and unassessed
gates. No actual validator engine has run; synthetic fixtures and script-driven
application state transitions are not distributed consensus or independent audits.

Local full source and remote main's wallet are separate histories. Do not claim
remote integration without reading and testing that exact source. Do not overwrite
wallet_state.py with certified_wallet.py or force-push the bundle over main.

The v0.12 helper tree exists without a commit/ref; the subsequent native-core
write was blocked by the platform. Earlier ABCI and payment-job uploads were also
blocked. Do not encode, split or use another route to retry blocked content. Only
supported authorized workflows may change these publication limits. Status-only
comments are distinct from source publication.

Next: real pinned upstream codec and four-validator protocol-1/2/3 acceptance,
then bounded authenticated storage, operator security, protected signing and
source-lineage reconciliation before public testnet. Keep exact evidence separate
from hopes, mock demonstrations, market-value claims or claims of novel cryptography.

## v0.13 compact-state checkpoint

Read docs/COMPACT_STATE.md before changing commitments. A fresh protocol-3 genesis
may explicitly set state_commitment=smt-v1; existing commitments must not change
when this field is absent. The new root includes every native row and is bound to
genesis and application height. Do not drop replay receipts or parent budget links.
Compact JSON proofs are not ICS23/IBC or ABCI ProofOps. Enforce caller-selected keys,
nondefault sibling encoding, atomic capacity checks and h+1 signed-root binding.
The new preflight is read-only and historical; never bypass the existing signing
wallet's freshness/checkpoint policy based on it. Node storage remains whole-state.
Full local verification is now 705 Python tests and 79 required files. No blocked
source upload is retried or rerouted; use local artifacts and status comments.
