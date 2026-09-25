# 1soft — pending-obligation wallet follow-up

This is a wallet-only follow-up to PR #5 at `11f1fd145f3b6c85882ab93af6dbc9a686015d6f`.
Native monetary, ABCI, execution, compact-proof and real-engine runner code is
unchanged. No Actions, paid compute, public deployment, DNS/site changes,
Resident/Luna/Psyche work, production keys or real funds are involved.

## Implemented behavior

`CertifiedWallet` now counts its already-signed, unresolved native payments against
account balances, individual grants and their immutable shared budgets. Fees count.
A review alone creates no hold; a durably recorded outgoing signature does.
Revalidation, decryption, expiry recheck and signature recording share the existing
SQLite transaction. Two processes using this journal cannot independently approve
more than the remaining aggregate allowance. The displayed confirmation binds the
local inventory as well as the authenticated chain snapshot.

Tested example: Raven signs 58 units plus a 2-unit fee against a 100-unit budget.
Atlas's 39-plus-2 request is refused before key decryption. Atlas's 38-plus-2 fits.
Pending is 100 while on-chain spent is still zero. After actual local application
execution and exact signed-receipt reconciliation, pending is zero and on-chain
spent remains 100. These are DEV atomic units, not dollars or reserve backing.

The native chain already rejected aggregate overspending. This fixes local
approval overcommit; it is not a newly discovered successful on-chain double spend.

## Holds and checkpoint continuity

Outgoing signatures remain pending until the verified full, unpruned state shows
the exact signed receipt, or a strictly later-than-valid_until height with the
transaction absent from the complete receipt table. Revocation, nonce advancement,
timeouts, endpoint labels and wall-clock passage alone do not release holds.
Incoming-key consent alone cannot spend and is not charged twice with its sponsor.
Historical decisions and their exact bytes remain exportable after reconciliation.

The wallet persists the verified witness. Subsequent checkpoints must extend the
observed signed header. Jumps require each intermediate signed header, at most 64,
with exact heights, block IDs, signatures and timestamp checks. This is static
validator trust, not a general dynamic light client or guaranteed-latest state.
Absence-based retirement is incompatible with silently pruning the receipt table.

## Commands and compatibility

Existing review/sign/export are preserved. New `sync` and `pending` commands use
`scripts/certified_wallet.py`, with the same required --genesis, --policy and
--journal options. Sync additionally requires --witness; --continuation is an
optional JSON array of intermediate signed headers. Pending rechecks saved
historical evidence without unlocking or requesting network data. Signing remains
interactive and never broadcasts. Export recovers the existing signature.

All participating signers must use ONE shared journal. Other journals/devices,
direct key access and whole-workspace rollback remain outside this coordination.
The legacy state_wallet outbox is preserved and still refuses protocol 3. Its
existing database is not migrated, overwritten or silently accepted as this
journal. Do not operate both outboxes against the same funds. Full product-level
wallet unification and legacy-decision migration remain unfinished.

Existing certificate-wallet decisions are reverified and counted, not erased or
resigned. Up to 10,000 decisions are scanned and full-state witnesses are used;
this is not a performance or production custody claim. A hostile local OS or
filesystem, weak passwords and compromised keys remain outside these protections.

## Verification evidence and source scopes

The complete local development package retains the previously reviewed recovery
add-on and passes 1,014 Python tests in 32 completed module processes, zero skips,
failures or errors, with exact unique-ID coverage. Its 49 new tests are included
in that total. The separate JavaScript reference passes 30. The 104-file required
inventory in THIS wallet-only branch differs from the complete local package's
108-file inventory because recovery is not republished here.

A local reconstruction of this exact branch source passed all 104 required-file
checks and 114 focused tests: 49 new obligations cases, 47 existing certified-
wallet cases and 18 budget integration cases. This is not a claim of rerunning the
entire remote branch suite. All published runtime/tests match tested local bytes.

Six deliberately weakened disposable implementations were caught by assertions:
shared/account pending caps, strict expiry, post-unlock freshness, stored signature
verification and logical-nonce exclusivity. An earlier continuation-guard mutation
was still rejected by the independent expected-height check and is NOT counted
as an assertion-based detection. Its initial report and logs are retained.

Three incomplete combined tool calls were rerun as separate completed modules;
partial logs are retained and excluded from the 1,014-case result. The untouched
parent reproduces the original local-overcommit defect in a failing regression.
Encrypted key operations, actual terminal interactions, SQLite concurrency,
process crashes and native application execution were tested. New committee
certificates are synthetic fixtures; no fresh CometBFT network ran here. Codex's
prior real-validator result is inherited node evidence, not new wallet evidence.

The downloadable complete package includes detailed WALLET_OBLIGATIONS.md,
WALLET_OBLIGATIONS_VERIFICATION.md, raw logs, exact case IDs, the executed example
and disposable fault-injection tools. These are developer checks, not an
independent security audit. This PR is a reviewed-development candidate, not
approval to hold customer money or start a public financial service.
