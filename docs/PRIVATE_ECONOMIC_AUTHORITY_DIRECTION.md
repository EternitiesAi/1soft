# Private economic authority direction

Selected 4 October 2026. This document chooses a product and architecture direction for evaluation. It does not change consensus, monetary rules, current release status, or the public claims allowed by the tested development evidence.

## October 5 frontier reassessment

The selected mission is retained and sharpened: private programmable money and
durable economic authority, with native 1soft settlement and separately qualified
connections to established commerce protocols. The immediate private-wallet gate
remains; AP2 mapping and extension of the existing native x402 path follow it.
Eternities ID owns identity; 1soft owns spending permission and obligations.
See [the source-backed refinement and ordered acceptance gates](FRONTIER_DIRECTION_20261005.md).
This is a strategic decision, not a new runtime capability or launch claim.

## The direction

Build 1soft toward **private programmable money and durable economic authority for people and persistent agents**.

The first product wedge is a private mission treasury for a small team of agents. A person funds one purpose. Several agents receive narrower grants against one aggregate allowance. Their combined spending remains bounded. Restarting or copying an agent does not replenish authority. An unresolved payment remains an obligation until authenticated evidence establishes its disposition. Revocation fences future authority without resetting prior expenditure or erasing existing commitments. A merchant can verify one purchase without seeing unrelated treasury activity.

This direction preserves the project's selected independent Layer 1 and native asset. It also adds a testable burden: the project must demonstrate that native execution provides guarantees that a confidential application on an existing settlement network cannot provide adequately.

The present P4 implementation is transparent. Private invoice content is application data encrypted for a trusted local caller; it is not shielded on-chain payment privacy. The shielded successor, production network, custody, economics, legal arrangements, and customer demand remain open gates.

## Why this is the highest-value candidate

Agent payments, spending limits, approval flows, scoped credentials, HTTP payment protocols, and selective disclosure already exist elsewhere. None of those individual features creates a durable advantage for 1soft. Native-coin status, encryption, test volume, receipt hashes, and visual polish also fail as standalone moats.

Reference points at selection include [Coinbase agent wallet controls](https://docs.cdp.coinbase.com/agentic-wallet/mcp/mcp-tools/show-wallet-app), [Tempo access-key limits](https://github.com/tempoxyz/tempo/blob/main/tips/tip-1011.md), [AWS AgentCore temporal policies](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-temporal.html), [Stripe's Machine Payments Protocol](https://stripe.com/blog/machine-payments-protocol), [the x402 exact payment scheme](https://github.com/x402-foundation/x402/blob/main/specs/schemes/exact/scheme_exact.md), and [Penumbra selective disclosure](https://guide.penumbra.zone/overview/disclosure). These sources show that substantial components have credible alternatives. They do not prove equivalent guarantees, market completeness, or novelty for 1soft's proposed combination.

The strongest candidate is the combination already implied by 1soft's working semantics:

- overlapping grants consume one shared parent allowance;
- the exact original payment and its reservation survive ambiguous failure;
- a lost reply does not authorize a second payment;
- collection and reconciliation remain separate;
- revocation changes future authority without rewriting financial history;
- one scoped proof can establish one purchase without exporting the full activity graph.

That combination can make 1soft an economic home for persistent agents rather than another wallet interface. It gives the native protocol a concrete purpose: enforce conservation, authority, continuity, and disclosure as one coherent transition.

## First product: a private mission treasury

The initial customer hypothesis is a creator, research group, or small studio operating several agents that buy research, rendering, storage, data, or other digital services.

The owner should be able to:

1. create a named mission and fund its treasury;
2. give each agent a narrower grant for approved actions, recipients, assets, and time;
3. see available funds separately from committed or unresolved obligations;
4. approve unusual actions without letting the agent approve its own expansion;
5. revoke current authority while retaining the truth about earlier spend and pending payments;
6. recover after interruption without re-signing or silently retrying a purchase;
7. disclose one selected receipt to one merchant or auditor without exposing unrelated activity.

The premium experience should come from legibility and confidence. At every point, the user should understand what is available, what is committed, what each agent may do, what is uncertain, and what information another party will receive.

## Expansion path

If the first wedge survives feasibility and demand tests, expand in this order:

1. **Verifiable digital-artifact commerce.** Bind a versioned offer, original payment, delivered bytes, and scoped proof so that a buyer can recover the exact purchased result without another charge. Content identity does not prove accuracy, usefulness, ownership, or legal rights.
2. **Continuity accounts for long-lived agents.** Preserve services, subscriptions, obligations, financial history, and reviewed authority transitions across changes of device, runtime, or model. A copied model or memory must not receive duplicate spending authority.

The merchant wedge is nearest to today's implementation. The continuity account is the fullest long-term expression and carries larger unresolved custody, device-fencing, recovery, governance, and legal burdens.

## The decisive technical proof

The next architecture proof should use one parent treasury with 10 units remaining and two agents. Each agent has an overlapping grant capped at 8. Both prepare a purchase costing 6 units including fees against the same parent state.

The model must demonstrate all of the following:

1. at most one purchase can commit;
2. the losing purchase retains its original uncertain obligation until authenticated evidence establishes its disposition;
3. revoking one grant after preparation and before ordered execution rejects stale authority;
4. revocation does not reset aggregate expenditure, refill a grant, or erase an obligation;
5. restart after an ambiguous submission does not change those facts or create permission to re-sign;
6. the eventual merchant proof reveals only the selected transaction and the evidence required to verify it.

Use transparent executable witnesses first to settle the accounting and failure semantics. Label that result accurately: it proves a transition model, not privacy. Promotion then requires a source-pinned cryptographic design, exact proof obligations, versioned domains and parameters, measured coordination and proving costs, custody and recovery design, and independent specialist review.

## Architecture consequence

The selected private-state hypothesis consumes and recreates one committed parent-budget fragment on every delegated spend, alongside the relevant grant state and value notes. This prevents two agents from independently consuming the same remaining allowance, but it serializes that budget and creates witness-distribution, contention, and recovery costs.

The design must bind:

- native integer conservation and fee accounting;
- immutable parent and grant relationships;
- grant and aggregate counters that include the same units and fee;
- current authorization, epoch, revocation, and expiry state;
- unique consumption and authorized successor state;
- the original payer consent, merchant request, and receipt identity;
- durable local obligation state before external submission;
- authenticated execution evidence before reconciliation.

Historical value-note anchors and current authority state may require different admissibility rules. An agent must not select an old authority root to bypass a later revocation. A losing concurrent transaction may be rejected by consensus while remaining a signed local obligation whose safety to replace is still unknown.

Scoped disclosure should reveal selected openings and execution evidence without exporting a full viewing key or stable identifiers that expose the account's relationship graph. Penumbra is the first architectural reference for shielded state and selective disclosure. Its existence does not prove 1soft's overlapping-budget and failure-continuity extensions.

## Reuse and replacement boundary

Preserve as successor conformance requirements:

- current native conservation, fee, grant, and aggregate-budget rules;
- one serialized signing and reservation journal for the same funds;
- exact original signed or proved transaction bytes;
- durable one-attempt claims before key-free external I/O;
- separate collection and reconciliation;
- retained holds for unknown, expired, revoked, or conflicting obligations;
- independently selected trust and authenticated validator/state ancestry;
- merchant binding to the exact request, payment, and fulfilled resource.

Replace or separately qualify:

- transparent account, grant, budget, recipient, and relationship identifiers;
- full-history capsules used as ordinary merchant receipts;
- same-host coordination presented as cross-device safety;
- local software vaults presented as production custody;
- public-history indexing presented as private completeness.

## The native-network question

The independent Layer 1 remains the selected product contract. Before expensive public-network expansion, compare it with a confidential application on a mature settlement network under the same acceptance criteria: aggregate shared authority, ordered revocation, unresolved-obligation continuity, recovery, and scoped proof.

The native thesis gains support if existing rails require a trusted gateway that can silently broaden authority, drop obligations, or expose the activity graph. It loses support if an existing network can provide the same customer guarantees, security, and user experience at materially lower cost and with better distribution.

External stablecoin or fiat services may become explicit connectors. Their assurances must remain separate from native-chain guarantees, and independent external keys cannot inherit 1soft's shared-budget rules merely because the application displays them together.

## Demand test

Technical feasibility and customer demand are independent gates. Review five real multi-agent spending workflows with operators, using the present transparent DEV journey beside a clearly labelled storyboard of the proposed private experience. Ask each operator to identify information they would refuse to publish and how they handle crashes, duplicate attempts, revocation, and reconciliation today.

The first meaningful positive signal is two concrete pilot workflows with a decision owner, representative data, integration time, and a stated reason the combined privacy-and-continuity contract matters. General enthusiasm, speculative investment interest, or preference for a premium interface does not establish demand. No customer outreach is authorized or claimed by this document.

## Reconsideration conditions

Reconsider or stop this direction if:

- private shared state cannot preserve overlapping limits, live revocation, and uncertain obligations at usable latency, cost, and recovery complexity;
- the implementation requires dropping holds, automatically retrying ambiguous payments, resetting counters, broadening agent authority, or inventing unreviewed cryptography;
- an existing network can provide the same guarantees without a distinct 1soft chain;
- target teams consistently choose ordinary payment rails and conventional limits over the proposed combination;
- production custody, independent operation, security review, or applicable legal and partner requirements cannot be met responsibly.

## Evidence boundary at selection

The source reviewed for this decision is commit `de937919d09db2470f12f1811e734f873bd786cb`, whose exact tested tree is `34f82feb3207fdfe20d8eb5eaa9cb15fab5af4ca`; the same tree was merged as `2ec6a5436bfb73b87b3d40769924655fe8bafd72` in private PR 53. The [sanitized evidence summary](BROWSER_MERCHANT_ALPHA_EVIDENCE_20261004.md) records the retained result and archive identities, hashes, method, verifier boundary, and unsupported claims.

For that exact source, the current-source qualification passed 2,894 distinct Python tests in 17 groups and 72 JavaScript tests in 5 groups. The actual same-host four-validator scenario passed 20 checks, three development payments, and twelve original resource/proof downloads. Those results support the current transparent implementation and recovery semantics.

They do not establish shielded privacy, mainnet readiness, public economics, production custody, independent operators, global exactly-once execution, external merchant identity, useful inventory, customer demand, legal readiness, or financial value.

Related specifications: [product and monetary design](PRODUCT_AND_MONETARY_DESIGN.md), [private payments architecture](PRIVATE_PAYMENTS_ARCHITECTURE.md), [native budgets](NATIVE_BUDGETS.md), [durable alpha](DURABLE_ALPHA.md), [browser merchant delivery](BROWSER_MERCHANT_DELIVERY.md), and [roadmap](ROADMAP.md).
