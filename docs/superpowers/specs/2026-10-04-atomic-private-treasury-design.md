# Atomic private treasury payment component

Standing authorization: Dom requested continued autonomous 1soft development and
authorized merges. No paid compute, Actions, public deployment, DNS/site changes,
Resident/Luna/Psyche work, real funds, production keys or force pushes.

## Selected design

Build a separate local component and profile, preserving P1-P5 and the prior
authority lab byte-for-byte. One Halo2 circuit shares private cells for payment,
recipient, agent secret and fee across the parent/grant transition and value
spend. Two unlinked proofs are rejected as an architecture because they do not
establish hidden amount/recipient equality. Altering the existing P5 profile is
rejected because it changes accepted statements under an existing genesis.

The input is a treasury-restricted note bound to genesis, asset, mission, parent,
grant, epoch and enrolled agent key. It proves depth-four membership and unique
position-bound nullification. Input value = merchant value + change + fee, all
64-bit integers, with positive input, payment and change. Merchant note and
request commitment bind the same recipient and payment cells. Change retains
the input's treasury/grant/agent scope and expiry. Only the combined relation
is accepted by this local ledger; there is no ordinary-spend escape route.

Domains 300-304 cover restricted/merchant notes and value nullifiers; 400-420
cover new authority fragments and context; 425 covers the entire statement.
Public fields are the prior 20 meanings plus value anchor, value nullifier,
merchant output, change output and composite binding. This is a new profile,
not a P5 migration. The old lab and P5 do not accept its notes or proofs.

## Local execution and continuity

A trusted local ledger selects the exact current authority context, admitted
historical value roots, fee, epoch and execution height. SQLite BEGIN IMMEDIATE
serializes check-current, real proof verification, note/nullifier insertion,
authority successors, fee tally and receipt into one FULL-sync WAL transaction.
No partial commit is visible. Fresh genesis has two restricted input notes,
one parent cap10 and two overlapping grants cap8. Each initial payment4+fee2
is independently valid; ordering admits at most one. A refreshed payment2+fee2
exhausts the remaining parent4 exactly. Fee tally is a sink, not free minting.

An exact-byte obligation journal reserves an input before submission and stores
the original statement/proof. Claim-once precedes external execution. Missing,
stale, revoked, conflicting and expired outcomes retain the obligation. This
milestone provides no automatic clearing from local rejection, re-signing,
re-proving, retry or cross-device recovery. Only exact local executed receipt
can record the obligation; it is not validator-authenticated reconciliation.

## Tests and promotion boundary

Test native and circuit constraints independently, bypassing native validation
with MockProver for attacks. Generate and verify real proofs, refuse malformed
encoding/proofs, test stale authority and ordered revocation without changing
parent spend, and test transaction rollback/after-commit lost return/process
restart. Freeze real parameter/vk/proof fingerprints and exact source/log receipt.

Trusted local host, synthetic deterministic keys/randomness and coordinator
remain assumptions. No validator, wallet P5, merchant redemption, discovery,
owner enrollment/revocation signature, current-state certificate, scalable tree,
cross-device fencing, metadata privacy, public network, production custody,
independent cryptographic review or economic value is qualified. Consensus
integration must be a new separately pinned fresh-genesis protocol and real
engine gate. This local receipt must never be presented as paid consensus.

## Expiry decision

Restricted-note lifetime may exceed a current grant's expiry. This preserves
note data rather than broadening agent spending authority: every accepted spend
requires execution_height < valid_until <= grant_expiry. Merchant output expiry
is independent after payment. A note40/grant30/transactionuntil20 assignment is
valid; until31 is refused by both native validation and the circuit.
