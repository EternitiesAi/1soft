# Native-coin roadmap — current development gate

Updated 4 October 2026. Acceptance gates, not launch promises or dates. “Implemented” below means source exists and its stated development tests have passed; it does not mean production-ready.

| Milestone | Current state | Required evidence / next action |
|---|---|---|
| Private economic authority product direction | Selected for evaluation; transparent two-grant adversarial transition model implemented | Run the separate demand test and select one coherent cryptographic stack. The [shielded foundation](SHIELDED_PRIVACY_FOUNDATION.md) now includes an isolated note lab under qualification; it establishes neither implemented privacy nor product-market fit. |
| Native monetary rules and atomic block commit | Implemented development model | Continue invariants, crash/fault tests and independent review. |
| Native accounts, key rotation and scoped grants | Implemented | Production custody/recovery design and independent review remain. |
| Protocol-3 shared agent budgets | Implemented and exercised on local validators | Preserve one canonical signing/reservation path; cross-device coordination remains open. |
| Certified wallet, decision delivery and receipt reconciliation | Implemented development flow; root full-state wallet uses shared exact inclusion/post-expiry classification | Compact audit evidence is separate from wallet mutation. Persisted compact-only wallet synchronization and hostile-host custody remain open. |
| P4 encrypted journal backup and historical recovery | Implemented development component; [scope and verifier](../tools/protocol4-custody/README.md) | Recovery-only original wires, holds, attempts and saved receipts; private-key recovery, latestness and old-device fencing remain open. |
| Opt-in cloned-journal device fence | Implemented local trusted-POSIX-host seam for explicit `FencedApproval` callers | Chain-enforced or authenticated cross-host coordination, rollback protection, reservation recovery and default-path integration remain open. Direct approval bypass is explicit. |
| Guarded browser historical export | Explicit compressed attachment from the shared journal; [scope](BROWSER_HISTORY_BACKUP.md) | Qualify actual downloads/decryption and untouched financial actions on each revision. Private-key recovery, cross-device coordination and hostile-host custody remain separate gates. |
| Actual multi-validator chain | **Passed on one-host development networks**; exact 4 October P4 state-sync profiles independently semantically validated | Repeat on independently operated hosts and retain operator/network fault evidence. |
| Authenticated compact state/proofs | Implemented development path | Continue scale, pruning and adversarial proof testing. |
| Bounded ABCI state sync | Both registered P4 profiles passed for [one exact source tree](PROTOCOL4_REAL_ENGINE_SECURITY_PHASE2.md) with pinned CometBFT | Re-run after relevant source changes, then repeat across independent machines. |
| Crash/recovery and application checkpoints | Implemented development tooling | Coordinate validator consensus DB/signing-state recovery; power-loss and operator drills remain. |
| Shielded transaction laboratory | [Isolated transparent-witness source](../tools/shielded-note-lab/README.md) present and under qualification; privacy-proof benchmark source under qualification with Groth16/BN254/Poseidon2 and Halo2/Pasta IPA as experimental profiles | Complete exact-source qualification and review of the [note-transition specification](superpowers/specs/2026-10-04-shielded-note-lab-design.md) and [proof benchmark](../tools/privacy-proof-benchmark/README.md), including authorization, conservation, replay, refused-state invariance, export/reopen, competing cloned states, scoped disclosure and listed rejection cases. The profiles use different parameter models and are not a production proof-system selection or production privacy, consensus integration, network anonymity, custody, independent review, public-network readiness or real-funds safety. |
| Real network fault/security tests | Partial one-host evidence | Multi-host partitions, restarts, hostile peers, resource exhaustion and incident drills. |
| Final engine/protocol decision | CometBFT 0.38.25 pinned for current development | Upgrade/licensing/security lifecycle and validator-set evolution policy. |
| Snapshot pruning/history policy | Not complete; sequential read replay and complete bounded backup/read-store formats implemented | Bound long-term receipt growth and define retained history/snapshot availability. Faster historical reads and smaller physical proof/backup files do not extend logical history or constitute pruning. See [read-proof storage](READ_PROOF_STORAGE.md). |
| Independent operator testnet | Not started | Independent hosts/operators, seed/peer plan, monitoring, release artifacts and rollback/incident procedure. |
| Independent security review | Not started | External code/protocol/custody review before value-bearing use. |
| Public economics/genesis | Undecided | Supply, denomination, issuance/distribution and governance must be explicitly chosen and reviewed. |
| Public value-bearing network | Not started | Technical, economic, operational and applicable legal/partner gates satisfied. |

The shielded-note lab is a local semantic qualification gate. It provides no
zero-knowledge privacy, production readiness, public deployment or real-funds
support, and it does not select a production proof system. One shared lab state can serialize
spends; independent cloned states have no common consensus authority. Its results
do not qualify private shared budgets or global double-spend prevention.

The privacy-proof benchmark is a separate offline exact-source qualification
surface for a synthetic one-input/two-output relation. Its ephemeral setup and
listed rejection cases remain experimental evidence; source under qualification
does not establish a successful benchmark receipt or any production boundary.

The native coin and any future redeemable dollar instrument make different economic promises. No public supply, value, returns, reserve backing, banking relationship or partnership is implied. The static website remains separate from node/validator infrastructure.
