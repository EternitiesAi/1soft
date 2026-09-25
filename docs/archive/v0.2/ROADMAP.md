# Coin-first roadmap and acceptance gates

24 September 2026. These gates specify evidence, not release-date promises. The independent coin remains the first priority; the app is not a substitute.

## Gate A — Define and exercise native rules

This package makes a bounded start: signed native transfers, grants, fencing, receipts, deterministic replay and local durability tests. Expand with a precise monetary-policy decision, account creation, owner recovery, resource/admission rules and adversarial/property-based tests. Integrate shared budget-tree semantics explicitly rather than asserting that separate prototypes already compose.

Acceptance: a reviewed specification and reproducible traces of accepted and rejected transitions, including every administrative action. No undefined balance or authorization behavior. Existing 58 Python tests do not alone close this gate.

## Gate B — Choose and run the real chain

Pin and license-review one coherent engine. Port or implement the application rules in its production language and interfaces. Build nodes from source. Start a private multi-node development network, prove native signed transfers and account state agreement, and preserve commands, binaries/source hashes and execution evidence.

Acceptance: independent processes communicate and commit according to the selected consensus. A SQLite journal or multiple local replay databases is not this milestone. The previous Cosmos reference bootstrap remains unexecuted here.

## Gate C — Challenge network assumptions

Operate genuinely independent validators, document voting/concentration assumptions, test partitions, equivocation, rejoining, upgrades, bad proposals, saturation and recovery. Test failures before advertising latency or throughput. Audit key custody, genesis, dependency provenance and release signing.

Acceptance: explicit pass/fail/unassessed results under stated fault assumptions. Four processes owned by the founder are not four independent operators. An audit is external evidence, not a renamed local test suite.

## Gate D — Native wallet, explorer and usable applications

Connect a real signer and trusted confirmation interface to the chain. Build native transfers, account history, reliable explorer indexing, portable identity and agent grants. Demonstrate Luna2 plus an unrelated runtime. Make interrupted work and revoked authority behave predictably.

Acceptance: an outside developer can run a documented test integration; a nontechnical tester can understand limits and recover from ordinary failures. The current five-screen HTML concept is not this integration.

## Gate E — Interoperability and partner sandbox

Integrate one real payment-test route and one supported conversion route before broad asset expansion. Model explicit asset/network custody. Obtain card sandbox/program access through approved partners. Verify replay protection, authenticated webhooks, refunds, reconciliation, FX quote expiry, late capture and provider outages.

Acceptance: statements reconcile to independently obtained provider data. Never fund a second route merely because the first returned an unknown outcome. Avoid a custom bridge until a concrete requirement and security review justify it.

## Gate F — Issuance, custody and public readiness

Determine the responsible issuer and legal structure; arrange eligible backing/redemption where applicable, custody, capital and operating controls. Establish disputes, incident response, clear disclosures and appropriate licenses/partner agreements. Complete independent security work and a limited funded pilot.

Acceptance: genuine external readiness, not only complete screens and source code. No customer funds or public dollar issuance before this gate is approved. Launch scope, geography and limits follow the evidence.

## Working delivery structure

Maintain protocol/node, native-wallet SDK, agent-policy kernel, durable journal, provider adapters, explorer, web/mobile clients and operations as separately testable components. Final repository names and branding remain open. Publish protocol claims only when their supporting evidence exists.

## Monitoring

The Agent Finance Watch is scheduled for Monday mornings around 8 a.m. America/Chicago, starting 28 September 2026. It reviews the preceding week's standards, card/issuer developments, competing products and security changes. It reports material roadmap implications; it does not automatically deploy code or change monetary policy.
