# Native coin roadmap — acceptance gates, not launch promises

| Gate | Current status | Required evidence |
|---|---|---|
| Signed native monetary rules | Locally tested | Transfers, fees, signatures, nonce/replay controls, grants/fencing and conservation. |
| Deterministic block application | Locally tested | Isolated proposals, durable commit, crash recovery, replay-state hashing and private transport. |
| Official upstream wire compatibility | **Unassessed** | Successful codec build plus actual upstream-produced fixture checks. |
| Real multi-validator development chain | **Unassessed** | Pinned CometBFT binary, fresh genesis, signed native transfers, observed quorum loss/restoration, node recovery. |
| Final protocol/engine selection | Open | Comparative technical and security review; no consensus-code collage. |
| Scalable authenticated state | Not implemented | Bounded execution/storage costs, query proofs, history/pruning and state-sync policy. |
| Account and agent integration | Partial model only | Production key custody, registration/recovery, shared budgets and a verified runtime adapter. |
| Cash/multi-crypto/card integration | Not implemented | Real partners, authorization/reconciliation, custody and conversion accounting; no hidden liabilities. |
| Independent review and bounded testnet | Not started | Third-party review, independent operations, incident drills and measured network behavior. |
| Public value-bearing network | Not started | Satisfied technical, operational, economic and applicable legal/partner requirements. |

The native network coin and any redeemable dollar instrument remain different economic promises. No public supply, allocation, return, reserve or partnership is implied by this roadmap.
