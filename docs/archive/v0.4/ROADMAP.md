# Native coin roadmap — acceptance gates, not launch promises

Updated 24 September 2026 · v0.4

| Gate | Current status | Required evidence |
|---|---|---|
| Signed native monetary rules | Locally tested | Transfers, fees, signatures, nonces, constrained grants/fencing and supply conservation. |
| Deterministic block application | Locally tested | Isolated proposals, correct encoded byte bounds, atomic commit, crash recovery and full replay-state hashing. |
| Independent development certificate checks | Locally tested with synthetic fixtures | Source-derived header/vote vectors, all-signature verification, strict power quorum, pinned genesis, inclusion, h+1 state anchoring and exact requested-payment binding. Not a general light client. |
| Official upstream Go compatibility | **Unassessed** | Successful compilation and all actual upstream-generated codec fixtures. |
| Actual multi-validator development chain | **Unassessed** | Real engine, fresh genesis, native and delegated transactions, quorum behavior, node recovery and independently checked live certificates. |
| Real-network fault testing | Not executed | Engine/app crash permutations, partitions, equivocation/fork behavior and preserved evidence. |
| Final protocol/engine selection | Open | Comparative requirements, dependency/license/security review; no consensus-code collage. |
| Scalable authenticated state | Not implemented | Bounded storage/execution, query proofs, pruning/history and state-sync rules. |
| Production account/agent authorization | Partial separate models | Safe key custody, registration/recovery, shared budget enforcement and verified runtime integration. |
| Cash/multi-crypto/card integration | Not implemented | Suitable partners, real conversion/custody accounting and reconciled liability handling. |
| Independent review and bounded testnet | Not started | Third-party review, independent operations, incident drills and measured network behavior. |
| Public value-bearing network | Not started | Technical, economic, operational and applicable legal/partner requirements satisfied. |

The network coin and a redeemable dollar instrument make different economic promises. No public supply, allocation, return, reserve or partnership is implied. The existing website remains an interface concept, not proof of functional banking or network launch.
