# Native-coin roadmap — v0.5

24 September 2026. Acceptance gates, not launch promises or dates.

| Milestone | Current state | Required evidence / next action |
|---|---|---|
| Native monetary rules and block commit | Implemented development model | Continue invariants, adversarial validation, crash tests and independent review. |
| Post-genesis native account onboarding | Implemented for fresh protocol 2 | Two-sided signed funding, rollback, receipts and replay tested locally; actual engine gate outstanding. |
| Stable-account key rotation and scoped grants | Implemented for fresh protocol 2 | Native epoch invalidation and non-resetting caps tested; not lost-key recovery or production custody. |
| Static-genesis signed receipt verification | Implemented development verifier | Synthetic certificates and source-derived vectors; actual Go codec/live certificates unassessed. |
| Actual multi-validator chain | **Unassessed** | Both protocol versions must pass real-engine transfers, lifecycle, quorum and independent receipt tests. |
| Real network fault/security tests | Not executed | Engine/application crash ordering, partitions, equivocation and recovery evidence. |
| Final engine/protocol decision | Open | Workload, dependency, licensing, security and upgrade review; no consensus-code collage. |
| Scalable authenticated storage | Not implemented | Bounded execution/storage, compact queries, pruning, history and state sync. |
| Protected owner/agent account product | Partial executable models | Trusted signer/UI, account discovery, explicit recovery, external revocation and privacy design. |
| Single cross-route authorization budget | Not implemented | Atomic reservation/reconciliation across native, external journal and subdelegation. |
| Cash, other cryptos and cards | Not implemented | Appropriate partners, custody/conversion accounting, verified connectors and liability handling. |
| Independent review and bounded public testnet | Not started | Third-party review, independent operators, incident procedures and measured behavior. |
| Public value-bearing network | Not started | Technical, economic, operational and applicable legal/partner gates satisfied. |

The original native coin and a redeemable dollar instrument make different economic promises. No public supply, value, returns, reserve backing or partnership is implied. The inherited website remains a disconnected design concept.
