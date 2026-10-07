# Native-coin roadmap — current development gate

Updated 6 October 2026. Acceptance gates, not launch promises or dates. “Implemented” below means source exists and its stated development tests have passed; it does not mean production-ready.

The [October 5 frontier reassessment](FRONTIER_DIRECTION_20261005.md) retains the
private/native treasury mission and prioritizes safe P7 proving/custody first,
then extension of the existing native x402 path and a bounded AP2 mapping.
Identity is an authenticated input from Eternities ID; settlement through external
providers requires separate evidence and cannot inherit native-chain guarantees.
This is an ordered development plan, not a claim of new interoperability.

| Milestone | Current state | Required evidence / next action |
|---|---|---|
| Private economic authority product direction | Selected for evaluation; transparent two-grant adversarial transition model implemented | Run the separate demand test and select one coherent cryptographic stack. The [shielded foundation](SHIELDED_PRIVACY_FOUNDATION.md) now includes an isolated note lab under qualification; it establishes neither implemented privacy nor product-market fit. |
| Transparent Protocol 1 through Protocol 4 monetary rules and atomic block commit | Implemented development model | Continue invariants, crash/fault tests and independent review. Protocol 5 has a separate state and proof model. |
| Native accounts, key rotation and scoped grants | Implemented | Production custody/recovery design and independent review remain. |
| Protocol-3 shared agent budgets | Implemented and exercised on local validators | Preserve one canonical signing/reservation path; cross-device coordination remains open. |
| Certified wallet, decision delivery and receipt reconciliation | Implemented development flow; root full-state wallet uses shared exact inclusion/post-expiry classification | Compact audit evidence is separate from wallet mutation. Persisted compact-only wallet synchronization and hostile-host custody remain open. |
| P4 encrypted journal backup and historical recovery | Implemented development component; [scope and verifier](../tools/protocol4-custody/README.md) | Recovery-only original wires, holds, attempts and saved receipts; private-key recovery, latestness and old-device fencing remain open. |
| Opt-in cloned-journal device fence | Implemented local trusted-POSIX-host seam for explicit `FencedApproval` callers | Chain-enforced or authenticated cross-host coordination, rollback protection, reservation recovery and default-path integration remain open. Direct approval bypass is explicit. |
| Guarded browser historical export | Explicit compressed attachment from the shared journal; [scope](BROWSER_HISTORY_BACKUP.md) | Qualify actual downloads/decryption and untouched financial actions on each revision. Private-key recovery, cross-device coordination and hostile-host custody remain separate gates. |
| Protocol 1 through Protocol 4 multi-validator chain | **Passed on one-host development networks**; exact 4 October P4 state-sync profiles independently semantically validated | Repeat on independently operated hosts and retain operator/network fault evidence. |
| Protocol 1 through Protocol 4 authenticated compact state/proofs | Implemented development path | Continue scale, pruning and adversarial proof testing. Protocol 5 uses a separate finite note tree and complete bounded replay history. |
| Bounded ABCI state sync | Both registered P4 profiles passed for [one exact source tree](PROTOCOL4_REAL_ENGINE_SECURITY_PHASE2.md) with pinned CometBFT | Re-run after relevant source changes, then repeat across independent machines. |
| Protocol 5 finite shielded consensus | Separate [fresh-genesis profile](PROTOCOL5_SHIELDED_CONSENSUS.md) and [component](../tools/shielded-consensus/README.md) checker-qualified on one loopback host: actual Halo2 proof admission, four equal-power validators, global nullifier/output uniqueness, atomic recovery, and marker-only state sync | Repeat on independent hosts and hostile networks; add wallet scanning/recovery and production custody; complete independent cryptographic/security review. Anonymity, metadata resistance, scaling, exchange readiness, public-network readiness, real-funds safety and production proof-system selection remain unestablished. |
| Crash/recovery and application checkpoints | Implemented development tooling | Coordinate validator consensus DB/signing-state recovery; power-loss and operator drills remain. |
| Shielded transaction laboratory | [Isolated transparent-witness source](../tools/shielded-note-lab/README.md) remains separate from consensus; the historical benchmark retains Groth16/BN254/Poseidon2 and Halo2/Pasta IPA experimental profiles, and its Halo2 exact-source verifier passed on the qualified implementation source | Complete remaining exact-source qualification and review of the [note-transition specification](superpowers/specs/2026-10-04-shielded-note-lab-design.md) and [proof benchmark](../tools/privacy-proof-benchmark/README.md), including authorization, conservation, replay, refused-state invariance, export/reopen, competing cloned states, scoped disclosure and listed rejection cases. The profiles use different parameter models and are not a production proof-system selection or production privacy, Protocol 5 consensus evidence, network anonymity, custody, independent review, public-network readiness or real-funds safety. |
| Real network fault/security tests | Partial one-host evidence | Multi-host partitions, restarts, hostile peers, resource exhaustion and incident drills. |
| Final engine/protocol decision | CometBFT 0.38.25 pinned for current development | Upgrade/licensing/security lifecycle and validator-set evolution policy. |
| Protocol 1 through Protocol 4 snapshot pruning/history policy | Not complete; sequential read replay and complete bounded backup/read-store formats implemented | Bound long-term receipt growth and define retained history/snapshot availability. Faster historical reads and smaller physical proof/backup files do not extend logical history or constitute pruning. Protocol 5's deliberately finite history is not a scalable replacement. See [read-proof storage](READ_PROOF_STORAGE.md). |
| Independent operator testnet | Not started | Independent hosts/operators, seed/peer plan, monitoring, release artifacts and rollback/incident procedure. |
| Independent security review | Not started | External code/protocol/custody review before value-bearing use. |
| Public economics/genesis | Undecided | Supply, denomination, issuance/distribution and governance must be explicitly chosen and reviewed. |
| Public value-bearing network | Not started | Technical, economic, operational and applicable legal/partner gates satisfied. |

The shielded-note lab is a local semantic qualification gate. It provides no
zero-knowledge privacy, production readiness, public deployment or real-funds
support, and it does not select a production proof system. One shared lab state can serialize
spends; independent cloned states have no common consensus authority. Its results
do not qualify private shared budgets or global double-spend prevention.

The historical privacy-proof benchmark is a separate offline exact-source
qualification surface for a synthetic one-input/two-output relation. Its Halo2
profile passed its source-bound verifier for the qualified implementation source,
but it retains a different circuit identity from Protocol 5. Its listed rejection
cases do not qualify Protocol 5 consensus and do not select a production proof
system or establish any production boundary.

Protocol 5 is a finite consensus and recovery qualifier. Its real-engine receipts
cover one host, synthetic notes, fresh validators, actual proof acceptance,
restart/fault cases and marker-only state sync. They do not establish a scalable
pool, independent operation or review, wallet/custody safety, transaction-graph or
network anonymity, metadata resistance, exchange readiness, public deployment or
real-funds use.

The native coin and any future redeemable dollar instrument make different economic promises. No public supply, value, returns, reserve backing, banking relationship or partnership is implied. The static website remains separate from node/validator infrastructure.

## Later Protocol 5 wallet continuity

The [finite trusted-host wallet](PROTOCOL5_WALLET_CONTINUITY.md) adds recipient-key payments, exact
lost-return recovery, selected-output capsules, authenticated H+1 reconciliation
and one-attempt delivery. These later controller-only additions preserve the
existing circuit/profile/KAT/worker and historical qualification identities.
They do not establish production custody, privacy, public deployment or real-funds safety.

## Private shared allowance proof milestone

The [isolated authority lab](PRIVATE_AUTHORITY_PROOF_LAB.md) now generates and verifies actual Halo2
proofs for hidden shared allowance successors and ordered revocation. Its trusted
local context is outside consensus; it has no payment or wallet caller. The
separate atomic treasury component below adds local value-note composition;
authenticated validator authority and wallet integration remain required.

## Atomic private treasury payment component

The [separately versioned component](ATOMIC_PRIVATE_TREASURY.md) links a conserved private note
payment with exact shared allowance debits and durable local obligation retention.
It preserves the earlier runtime contracts. Local execution and real proofs do
not establish validator consensus, production privacy/custody or launch readiness.

## Protocol 6 atomic treasury validator development

The separately pinned [P6 treasury protocol](PROTOCOL6_TREASURY.md) promotes the frozen combined payment/allowance relation into a finite four-validator development application with atomic recovery and signed AS-OF full-state evidence. Existing protocols remain separate. Static genesis grants, one-host validators, bounded trusted-host verification, no owner lifecycle, wallet integration or merchant redemption are explicit limits. The [clean-source real-engine receipt](../evidence/protocol6-treasury/20261004/engine-qualified-01.json) passed all 18 checks; [review and validation scope](../evidence/protocol6-treasury/20261004/AI_REVIEW.md) records the failures, repairs and remaining gates.

## Certified treasury controller and release gates

The [P6 certified journal](PROTOCOL6_CERTIFIED_WALLET.md) retains exact prepared payments, claims one delivery attempt before loopback I/O and records only independently replayed signed inclusion. The [deployment readiness map](DEPLOYMENT_READINESS.md) separates development qualification from owner lifecycle, merchant/custody, scale, independent operators and public-launch gates. Exact wallet-engine evidence is registered after its clean-source run; the original P6 receipt remains scoped to its captured runtime.

## P7 authenticated owner lifecycle

The [owner treasury successor](PROTOCOL7_OWNER_TREASURY.md) adds canonical owner-signed enrollment, revocation and rotation to a new network-bound proof profile. Three fresh clean-source actual validator runs and strict replay checkers passed; original protocols and notes are not relabeled. The certified owner/payment client and production/operator/economic gates remain distinct.

## Certified P7 owner/payment developer path

The [typed P7 client](PROTOCOL7_CERTIFIED_CLIENT.md) now has25-check actual caller evidence for future-height owner execution, lost owner/payment acknowledgements, exact signed recovery, stale first-claim refusal and same-store restart. The P4 durable alpha remains the browser product. The P7 prover increment below closes bounded proof preparation; encrypted authentic-note custody/discovery remains next. Public launch, economics, independent operators and specialist review remain separate.

## Bounded P7 arbitrary payment preparation

The [P7 developer prover](PROTOCOL7_PROVER.md) now accepts canonical Assignment/Witness inputs, produces an independently randomized proof with the exact frozen identities, and atomically retains the exact payment in the certified journal. The [registered clean-source actual run](../evidence/protocol7-prover/20261005/prover-qualified-01.json) passed16 checks, including four-validator settlement, a deliberately lost acknowledgement, signed exact recovery, cold reopening, refusal of redelivery and validator restart. New prover/journal tests passed10 cases; Rust request/binary tests passed2; the existing real-proof journal regression passed10; adversarial receipt tests passed4.

Next qualify encrypted custody and authenticated import/re-spend of actual P7 restricted change notes. Viewing/disclosure cannot confer spend authority, imported owner sequence is provenance rather than note identity, and merchant-note redemption remains a distinct relation. These are synthetic one-host development receipts, not a complete private wallet or production release.


## P8 recipient-controlled spending component

The [separate P8 component](PROTOCOL8_RECIPIENT.md) makes received typed notes
spendable by their recipient key and conserves value across payment/change/fee.
The versioned validator application, encrypted recipient wallet and
[authenticated node recovery](PROTOCOL8_RECOVERY.md) have separately registered
native/actual-engine evidence. Recovery includes a real Comet light-client import,
lost final Apply re-offer, full replay, genuine post-sync recipient spend and
same-store restart. Existing P7 notes/authority are not reinterpreted.
The [protected operator workflow](PROTOCOL8_OPERATOR.md) adds an explicit fresh
workspace, static doctor, native store audit and foreground private application
launcher. Its [registered fresh actual caller receipt](../evidence/protocol8-operator/20261006/operator-02.json)
passed 11 operator checks alongside the unchanged 22-check recovery journey. Independent operators, signer
recovery, pruning/scale, P7 migration/shared owner composition, economics,
production privacy/custody and external specialist review remain distinct gates.

The [protected P8 wallet CLI](PROTOCOL8_WALLET_CLI.md) adds explicit local custody
commands over the unchanged encrypted recipient wallet. Its [registered fresh actual caller receipt](../evidence/protocol8-wallet-cli/20261006/wallet-cli-03.json)
passed 13 caller checks and the unchanged 22-check actual wallet journey.

The [local P8 payment caller](PROTOCOL8_PAYMENT_CALLER.md) now joins retained
wallet intent to one explicit loopback submission and signed reconciliation.
Its [fresh actual caller receipt](../evidence/protocol8-payment-caller/20261006/payment-02.json)
passed 13 caller checks and all 22 underlying actual wallet checks.

The [local P8 terminal console](PROTOCOL8_PAYMENT_CONSOLE.md) adds private original
intent review, exact confirmation and protected status/reconciliation. Its
[fresh actual receipt](../evidence/protocol8-payment-console/20261006/console-05.json)
passed 12 console, 13 payment and 22 actual wallet checks. Next: complete the local
receive, preparation and private delivery interface, then qualify independent
operators and production custody. No public release is inferred.

The additive [local wallet journey](PROTOCOL8_WALLET_JOURNEY.md) now exposes
observation, import, separate preparation confirmation, exact export and private
delivery. Its [fresh actual receipt](../evidence/protocol8-wallet-journey/20261007/journey-03.json)
passed all 14 journey, 12 console, 13 payment and 22 wallet checks. Wallet/core
runtime remains byte-compatible with PR83. The recipient re-spend is prepared,
exported and natively verified; no second chain execution is claimed.

The separate [P8 local browser alpha](PROTOCOL8_LOCAL_ALPHA.md) now has a
[fresh two-wallet actual receipt](../evidence/protocol8-alpha/20261007/alpha-05.json)
and [independent three-proof, three-signed-state native replay](../evidence/protocol8-alpha/20261007/alpha-independent-replay.json).
Both synthetic payments executed on the disposable four-validator network;
Carol's second payment used Bob's delivered funds. Both one-attempt lost replies
were recovered through signed AS-OF state, with repeat sends refused before I/O.
The new batch startup preserves circuit/wire/profile/monetary rules while changing
two protected startup files and worker/runtime pins. Existing wallets refuse;
no existing custody is repinned or migrated. Local startup improvement is a
separate component measurement. Independent operators, production custody,
hostile-host/browser privacy, freshness and public deployment remain open.
