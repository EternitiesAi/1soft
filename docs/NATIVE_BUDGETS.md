# Shared native agent budgets — protocol 3 / v0.12

September 24, 2026 (America/Chicago). Development-only native execution rules.
This is not a public coin, a stablecoin issuer, a launched validator network, or an
independent security audit. Public supply, allocations, ticker and fees are not
selected by this protocol experiment.

## The problem and the implemented rule

Previously, separate agent grants had separate spending caps. They did not share
an enforced aggregate limit. Protocol 3 adds an owner-authorized native budget to
which every agent grant must belong. The ledger checks both remaining limits for
every delegated native transfer, including its native transaction fee:

    agent_spent + payment + fee <= agent_cap
    budget_spent + payment + fee <= budget_cap

A worked test creates a 100-atomic-unit budget and grants Raven and Atlas an
individual 100-unit cap each. Raven pays 58 plus a fee of 2, consuming 60. Atlas's
39-plus-2 debit is rejected because the aggregate would be 101. Atlas can instead
pay 38 plus 2, bringing the aggregate to exactly 100. Increasing the number of
grants does not increase this budget's actual spending allowance.

The individual grant caps are overlapping ceilings, not separately reserved
shares. This is useful for a pool of workers competing for one project allowance.
It does not establish fairness: the first eligible committed payments can consume
the available budget before other workers. Unused individual allowances are not
promises that those amounts remain available to each agent.

## Native operations

An owner signs a budget operation, using the ordinary native envelope, nonce,
expiry, fee cap, chain and genesis binding. The new operation shapes are:

```json
{"type":"budget_create","id":"project-149","cap":100,"expires":500,"recipients":["MERCHANT_ACCOUNT"]}
```

```json
{"type":"budget_revoke","id":"project-149"}
```

`MERCHANT_ACCOUNT` must be replaced with an existing native account, not an
unverified display name. Quantities are integer atomic development units, not USD.
Budget creation pays the ordinary owner administration fee; it does not mint or
move 100 coins into escrow. Its cap is not itself a debit.

Every protocol-3 `grant` additionally requires `budget_id`, the owner's budget
label. A grant must belong to the same owner and authority epoch. Its cap cannot
exceed the parent cap, its expiry cannot outlive the parent, and its permitted
recipients must be a subset of the parent's recipients. A transfer's existing
`grant_id` determines the budget; a worker cannot select a different budget in
the payment. Grant-to-budget links cannot be edited or recycled.

Budget labels are permanently owner-scoped. Revoking a budget disables all grants
bound to it without resetting historical expenditure. Revoking one grant does not
return its spent amount to the pool. Fencing or rotating the account's controlling
key invalidates older budgets and grants through their authority epoch while
preserving identities and history. The owner can explicitly authorize a different
new budget; the system does not silently reset, extend or refill the old one.

Agent keys cannot create, revoke or rebind budgets. Direct owner-signed spending
is intentionally outside agent-budget caps: the account owner retains control of
its funds and can create multiple explicitly authorized budgets. This is not an
unavoidable account-wide spend limit or a restriction on the account owner.

## Atomic accounting and consensus-application integration

The native execution transaction updates the payment recipient, payer, fee
account, grant counter, grant spending, budget spending and receipt together.
Every committed budget reconciles to the sum of its linked grants' lifetime
spending. A rejection does not partially charge the budget, move funds, consume
an authorization counter or emit an accepted receipt. Creation/revocation also
roll back if the payer cannot afford the administration fee.

Preliminary checks can independently accept two transactions that together would
exceed a budget. Ordered proposal evaluation rechecks against staged prior
transactions. Proposal construction omits the excess transaction; proposal
validation rejects the overspending list. Defensive execution of an already
supplied block returns failure for the excess transaction and preserves the
successful prior transaction. These are tested application semantics, not evidence
that actual validators agreed on a block.

Protocol-3 snapshots include `budgets` and `grant_budgets` in their application
state commitment. Restore checks the relationships and reconciled counters. The
existing fixed-genesis certificate verifier supports that version's exact table
set and signed application hash. The local certificate-backed wallet displays
both the individual allowance and the shared remainder and checks both before
unlocking. It still verifies a historical snapshot, not guaranteed latest state;
actual native execution must independently check the current counters again.

## Explicit version boundary

This feature is enabled only by `protocol_version: 3` in a fresh development
genesis. There is no migration of protocol-1/2 databases or automatic opt-in.
Protocol-1/2 snapshot table sets and rules are unchanged. Golden transaction,
receipt, state and application-hash vectors captured from the v0.11 parent are
replayed unchanged in the new tests. A failed reopen with a different genesis
must not add protocol-3 tables to a protocol-2 database.

The full local application, local certificate-backed wallet, receipt verifier,
and real-network acceptance plan are updated. The separate `wallet_state.py`
implementation on remote main is not overwritten or claimed integrated. The
protocol-3 engine plan is executable authoring, but its validator path has not
run in this environment. Protocols 1 and 2 remain required engine test cases too.

## What is not promised

These budgets are native-asset permissions, not escrow, available-balance
reservations, USD backing, automatic refunds, recurring monthly quotas,
cross-chain/card limits, or protection against a malicious account owner.
Budget creation grants no additional coin balance. Multiple budgets may compete
for the same account balance, and owner payments may reduce available funds.
The ledger rejects an otherwise authorized payment when the balance is insufficient.

There is no arbitrary-depth delegation tree, an agent's right to give its worker
new authority, or atomic commitment with a bank/card ledger. Existing local jobs
and payment journals remain distinct from native monetary state. A card liability
cannot be canceled by a native budget revocation.

A development bound limits an owner to 128 lifetime budget records and each
budget to 128 grant records. Reaching those limits is a documented prototype
limit, not a production resource/economic design. Full-state snapshots, repeated
state scans and synthetic static-validator witnesses remain scalability and
trust limitations. No public throughput, decentralized-security or custody claim
follows from the tests.

## Local verification

With the pinned installed dependencies, no Actions are needed:

```sh
python scripts/verify_checkout.py
PYTHONPATH=src:tests python -m unittest discover -s tests -p test_native_budgets.py -v
PYTHONPATH=src:tests python -m unittest discover -s tests -p test_budget_integration.py -v
```

These two modules contain 36 and 18 cases respectively: 54 total, included in the
complete 623-case local suite. Run the actual official-engine gates separately:

```sh
python scripts/local_dev.py network --engine /absolute/path/to/cometbft
```

That command requires the existing pinned upstream codec probe and genuine
four-validator cases for all three explicit protocol versions. It must report
unassessed rather than substitute a mock engine when prerequisites are absent.

Related authorization and spending-limit ideas have established prior art. This
is original project integration, not a claim to have invented allowances,
cryptography or consensus. The source-review record includes Cosmos SDK's
MsgSendAuthorization approach; no upstream implementation was copied wholesale.
