# 1soft mission and development priorities after the October 5 frontier sweep

Decision date: 2026-10-05. Strategic refinement and planned work, not an implementation or deployment claim. Runtime baseline inspected clean at `448a8c3aee34a012c9f2f32de560fea1f0a745cd`. Earlier qualification remains tied to its recorded source.

## Mission

Build **private programmable money and durable spending authority for people and persistent agents**, with an independent native network and asset, and an account layer that can connect to established commerce protocols and separately qualified payment routes.

The product should make it clear who authorized a purchase, which budget it consumes, what remains available or unresolved, and which authenticated evidence establishes its outcome. A changed model, copied runtime, lost response or recovery must not silently create more permission to spend.

The first customer hypothesis remains a creator or small team operating agents that buy research, data, rendering, storage and other digital services. The first wedge remains the private mission treasury. Demand, native-network advantage and production privacy remain hypotheses to qualify.

## What changed

The [October 5 canon sweep](https://github.com/EternitiesAi/eternities-canon/blob/9f8887aa5b1c6a0e158c0399c641fdaa9f7e52a0/research/frontier-intelligence/2026-10-05-sweep.md), P0 section 5, makes interoperability an explicit priority. The refinement is to connect an existing durable economic core to external commerce formats rather than duplicate their handshakes.

This is a priority/interface change, not a consensus rewrite or abandonment of the native coin. Existing [product architecture](PRODUCT_AND_MONETARY_DESIGN.md) and [cards/multiple-asset proposal](CARDS_AND_MULTI_ASSET.md) already separate native rules, account policy and provider services.

A bounded current-source inspection also found an existing native x402 envelope in [payment_x402.py](../tools/private-payments/src/payment_x402.py) and existing [merchant delivery](BROWSER_MERCHANT_DELIVERY.md). Therefore a blanket assertion that x402 is absent from 1soft is incorrect. The missing work is narrower: AP2 mapping, portable authenticated identity/authority input, selected-profile integration, and actual external-route adapters.

## Boundaries the sweep needs us to preserve

| Object | Owner or meaning | Boundary |
|---|---|---|
| Durable identity and lineage | Eternities ID | An identity relationship does not authorize spending or transfer debts/ownership. |
| Runtime/task credential | Identity owner; consumed by 1soft | Short-lived evidence about a caller, separately bound to a current grant. |
| Economic grant and reservation | 1soft | Exact purpose, payer, recipient, asset, amount/fee, expiry and applicable authority generation. |
| AP2/x402/MPP | Commerce or payment protocols | They are not coins or settlement networks; external claims cannot enlarge local authority. |
| Native 1soft transaction | Selected native profile | Its proof/receipt establishes only that profile's execution under declared validator trust. |
| Card/stablecoin/bank provider event | Separately qualified connector | Specific authentication, settlement/liability and reconciliation rules; no inherited native guarantees. |
| Reputation or social consequence | Eternities Network | A settlement record can be an input, not an automatic reputation decision. |

Do not duplicate EID, the Browser sandbox, A2A civilization semantics, or Resident cognition here. Define interfaces with those owners; this decision does not authorize changes or messages in their lanes.

## Current implementation versus missing work

- P4 provides a transparent local developer account/merchant flow with retained payment and resource recovery. Its x402 envelope is an experimental `1soft-p4` scheme for valueless native DEV, not external stablecoin support or production x402 acceptance.
- P7 provides a separate finite proof-backed owner/grant and payment development profile. Its bounded arbitrary-input developer prover now composes with the certified journal and has16-check actual validator evidence. Encrypted authentic-note custody/discovery remains open. Public mission/parent/grant identifiers still correlate activity.
- [SettlementJournal](../src/settlement_journal.py) is a trusted-fixture multi-asset accounting model. It has no authenticated provider connector and must not become a live API by relabeling its methods.
- Bounded P7 proof preparation is qualified for canonical developer inputs on one host. Encrypted custody/discovery, selected disclosure, merchant redemption, cross-device coordination, scalable history and independent operation remain distinct gates.
- No AP2 interface was found in the inspected current paths. That scoped result is not an exhaustive absence claim.
- A common account display does not create one atomic shared budget across independently controlled external accounts. External holds, delayed captures, refunds and liability exceptions require their own reconciliation.

## Development order

### 1. Complete the selected private wallet foundation

Continue the [live readiness gate](DEPLOYMENT_READINESS.md). The bounded P7 prover is now registered at clean execution source ad4d011. Next compose encrypted custody and authenticated import/discovery of actual restricted change-note openings with the certified journal, then prove and spend a later change note. Keep selected-output disclosure separate from spend permission. Merchant outputs have a distinct P7 domain; their redemption requires a separate relation.

Acceptance: actual fresh-network prepare, verify, submit, recipient import/spend, reopen and selected disclosure; refuse wrong profile/genesis/owner generation, altered witnesses and forged receipts; retain original obligations after an intentionally lost return. A detector or viewing capability cannot gain spend authority. Do not inherit P5 evidence or claim activity-graph privacy from note encryption.

### 2. Extend existing machine-commerce boundaries

Use existing invoice/request/journal and x402 structures. Define one versioned adapter contract for a purchase, authenticated caller, explicit authority, merchant/quote, selected protocol, asset/network, amount/fees and expiry.

Implement the smallest AP2 mapping justified by a pinned specification. Current [AP2 v0.2](https://ap2-protocol.org/ap2/specification/) separates linked Checkout and Payment Mandates, direct/autonomous use and deterministic verification. A signed mandate does not replace a current 1soft grant. Unsupported constraints must require explicit review or refusal.

First qualify a local native DEV path; connect the selected P7 wallet only after its prerequisite gate. Do not call a custom native x402 scheme a supported USDC route, or claim interoperability from a self-authored parser alone. An actual independently implemented caller/parser and version-specific conformance evidence are required.

### 3. Qualify recovery, authority and identity through one complete purchase

Demonstrate one owner-approved service purchase through the canonical journal, selected protocol adapter, actual local native settlement and verified resource receipt. Inject a lost response and restart; recover the same purchase without creating a new payment.

Reject changed recipient/resource/asset/amount, stale/revoked authority, duplicate challenges, wrong genesis, unsupported identity proof and unapproved routing. Authorization and service routing must agree on the exact request. A merchant page, response, screenshot or tool-return instruction cannot widen permission.

Preserve separate evidence for permission, reservation, execution, settlement and delivery. An independent trace checker should identify the first point an unauthorized action or false completion became possible, even if a later final result appears successful.

For identity use a reviewed ID-owner interface with synthetic keys in the local demonstration. [WIMSE AI-agent identity](https://datatracker.ietf.org/doc/draft-ni-wimse-ai-agent-identity/) is an individual Internet-Draft, not an endorsed standard or an existing EID integration. No lineage/personhood or real attestation claim follows from the fixture.

### 4. Add external routes only behind qualified connectors

A later synthetic provider fixture can exercise typed holds/captures/refunds and late/conflicting evidence, but is not external settlement. Actual use requires an explicitly authorized connector, protected keys, authenticated provider evidence and separately approved partners/targets.

An unknown purchase must not trigger fallback to another currency or route. [CDP settlement-pending guidance](https://docs.cdp.coinbase.com/x402/seller/settlement-pending) explicitly allows a 500/success:false after broadcast without terminal failure; reconcile the original transaction. Distinguish its documented same-payload reconciliation from issuing another payment. Preserve P7's current one-attempt boundary until a different adapter retry contract is explicitly qualified.

Use profile/route-specific verifiers. Neither a common receipt envelope nor native P7 proof validates an external USDC/card settlement.

## Later research and reconsideration

Private rule-compliance proofs, threshold recovery, cross-device obligation continuity and verifiable-result commerce remain valuable successor research. FHE infrastructure, new mints, a new universal commerce protocol, speculative bridges and unrelated consensus forks are deferred while the core product remains incomplete.

Retain the native-network comparison and demand test from [the original direction](PRIVATE_ECONOMIC_AUTHORITY_DIRECTION.md). Demonstrate what native execution improves over an application on an existing network, measure wallet/proving/integration cost, and seek actual pilot workflows only when outreach is authorized. No listing, valuation, return, banking or reserve claim follows from the roadmap.

## Daily check and evidence receipt

Frontier check: 2026-10-05 | sweep: 2026-10-05-sweep.md@8f8b7fa5db4d559c9441936022d2511209059957 | lane: 1soft | result: preserve private/native treasury; prioritize existing commerce adapter extension and identity/authority/provider evidence separation.

Canon commit: `9f8887aa5b1c6a0e158c0399c641fdaa9f7e52a0`. Full sweep, index and daily protocol read from authenticated read-only GitHub access; Git blob identities and local SHA-256 receipts checked. Primary AP2/A2A-x402, WIMSE, CDP pending-settlement guidance and x402 advisory inspected. [GHSA-qr2g-p6q7-w82m](https://github.com/x402-foundation/x402/security/advisories/GHSA-qr2g-p6q7-w82m) is a March 6, 2026 advisory with specific SDK floors, not a new October exploit or evidence of compromise here. Exact selected dependencies and transitive licenses need review before adoption; metadata alone is insufficient.

This change updates documentation and priorities only. No protocol, tests, funds, provider integration, deployment, DNS or other project changed. Source qualification is not transferred from the runtime baseline to a documentation revision.
