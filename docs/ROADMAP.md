# Native-coin roadmap — current development gate

Updated 2 October 2026. Acceptance gates, not launch promises or dates. “Implemented” below means source exists and its stated development tests have passed; it does not mean production-ready.

| Milestone | Current state | Required evidence / next action |
|---|---|---|
| Private economic authority product direction | Selected for evaluation; [scope and falsification gates](PRIVATE_ECONOMIC_AUTHORITY_DIRECTION.md) | Run the two-grant adversarial transition model and separate demand test. Direction selection does not implement privacy or establish product-market fit. |
| Native monetary rules and atomic block commit | Implemented development model | Continue invariants, crash/fault tests and independent review. |
| Native accounts, key rotation and scoped grants | Implemented | Production custody/recovery design and independent review remain. |
| Protocol-3 shared agent budgets | Implemented and exercised on local validators | Preserve one canonical signing/reservation path; cross-device coordination remains open. |
| Certified wallet, decision delivery and receipt reconciliation | Implemented development flow | Consolidate one source lineage; hardware/hostile-host custody and cross-device operation remain open. |
| P4 encrypted journal backup and historical recovery | Implemented development component; [scope and verifier](../tools/protocol4-custody/README.md) | Recovery-only original wires, holds, attempts and saved receipts; private-key recovery, latestness and old-device fencing remain open. |
| Guarded browser historical export | Explicit compressed attachment from the shared journal; [scope](BROWSER_HISTORY_BACKUP.md) | Qualify actual downloads/decryption and untouched financial actions on each revision. Private-key recovery, cross-device coordination and hostile-host custody remain separate gates. |
| Actual multi-validator chain | **Passed on one-host development networks** | Repeat on independently operated hosts and retain operator/network fault evidence. |
| Authenticated compact state/proofs | Implemented development path | Continue scale, pruning and adversarial proof testing. |
| Bounded ABCI state sync | Implemented development path; qualify each revision with its own engine receipt | Run `run_state_sync.py` against pinned CometBFT for each candidate, then repeat across independent machines. |
| Crash/recovery and application checkpoints | Implemented development tooling | Coordinate validator consensus DB/signing-state recovery; power-loss and operator drills remain. |
| Real network fault/security tests | Partial one-host evidence | Multi-host partitions, restarts, hostile peers, resource exhaustion and incident drills. |
| Final engine/protocol decision | CometBFT 0.38.25 pinned for current development | Upgrade/licensing/security lifecycle and validator-set evolution policy. |
| Snapshot pruning/history policy | Not complete; sequential read replay and complete bounded backup/read-store formats implemented | Bound long-term receipt growth and define retained history/snapshot availability. Faster historical reads and smaller physical proof/backup files do not extend logical history or constitute pruning. See [read-proof storage](READ_PROOF_STORAGE.md). |
| Independent operator testnet | Not started | Independent hosts/operators, seed/peer plan, monitoring, release artifacts and rollback/incident procedure. |
| Independent security review | Not started | External code/protocol/custody review before value-bearing use. |
| Public economics/genesis | Undecided | Supply, denomination, issuance/distribution and governance must be explicitly chosen and reviewed. |
| Public value-bearing network | Not started | Technical, economic, operational and applicable legal/partner gates satisfied. |

The native coin and any future redeemable dollar instrument make different economic promises. No public supply, value, returns, reserve backing, banking relationship or partnership is implied. The static website remains separate from node/validator infrastructure.
