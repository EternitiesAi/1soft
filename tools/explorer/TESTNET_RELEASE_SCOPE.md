# 1soft v0.1 development testnet — proposed integration target

28 September 2026. This file scopes the next integration milestone. It does not
merge branches, approve a release, declare completion percentages or set a launch
date. Dom's product goal includes a coin, wallet and ecosystem; the first testnet
release should make one ordinary user journey work end to end.

## Release demonstration

From one pinned release checkout: start the existing local validator network,
create/open a development account, authorize bounded agent grants, prepare and sign
through the one shared wallet journal, deliver the original decision, recover a
lost reply, and reconcile its receipt. The explorer must show the exact native
payment, account, shared-budget spending and verification scope. Stop and reopen
both wallet and explorer; do not generate a replacement signature. Start a fresh
observer, state-sync it, and demonstrate a payment committed after its snapshot.

One release checkout and one test matrix are the evidence unit. Stacked PRs are
review units, not release qualification. Existing source-specific test reports must
not be added together and described as a passing integrated candidate.

## What is now available, versus what remains

The inherited native execution, budget/signing/delivery and state-sync components
have their stated development tests; PR #14 has one-host real-validator evidence.
PR #15 local history retention and PR #16 portable receipts remain separate newer
source changes. This explorer is additive to the PR #16 lineage. No claim is made
that PR #13's divergent attempt-consent follow-up or the unpublished/partial catch-up
and operator-kit lines have been integrated. Resolve those explicitly during release
review instead of assuming every historical PR belongs to the current branch.

The next integration freeze should identify which optional modules are in v0.1,
run the entire current core plus selected product suites on that exact tree, and
retain real-engine default/bounded-history/state-sync/explorer execution evidence.
The remaining final-Apply engine kill/restart case still needs actual process
qualification. Codex is useful for those engine/system gates, not required to build
ordinary source changes or this local explorer.

After the local release is reproducible, qualify it with independently administered
validator hosts, explicit operator procedures and fault drills. A four-process
single-host run does not satisfy that independent-host gate. No external machines,
paid hosting or deployment are provisioned by this proposal.

## Protocol development discipline

Non-consensus features such as this derived explorer can remain separately reviewed.
Changes to receipt retention in consensus, replay rules, validator-set evolution,
transaction encoding, fee/supply rules or state commitments need a versioned proposal,
reference vectors, migration/activation specification and upgrade-network tests.
Do not change all of those simultaneously to make the testnet look more complete.
An improvement-proposal document records a design decision; it does not itself
activate a fork or authorize deployment. Independent review is required before
customer value depends on any implementation.

## Explicit exclusions from v0.1 development scope

Value-bearing mainnet, USD redemption/reserves, banking/cards, exchange liquidity,
bridges, production custody, hardware-wallet certification and commercial security
assurances are not established. Public supply/denominations/issuance and governance
still need explicit choices. An explorer displaying conserved DEV atomic units
must not imply a USD peg, market value or a promise of returns.
