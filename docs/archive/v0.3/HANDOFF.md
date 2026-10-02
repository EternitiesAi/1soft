# Continuation handoff — native coin v0.3

## Standing lane

The founder wants an independent Layer 1 with a genuine native coin, agent-native economic continuity and a simple financial account around it. Coin implementation is the priority. Branding and monetary policy remain open. No public launch, movement of funds, issuer application or existing remote-repository change occurred in this continuation.

## What exists

Original signed native ledger and settlement model from v0.2; new deterministic block application; a private Unix-socket ABCI adapter targeting CometBFT v0.38.25; local process tests; a real-engine runner; upstream-codec gate; local Git history; unchanged account concept.

The native core and external settlement journal are still separate. The JavaScript parent-budget reference is still separate. Do not imply an integrated cross-rail budget or a production wallet.

## Proven now

122 Python tests; 30 prior JavaScript tests; 39 checks across four scripted application processes; three targeted mutant defects detected. Staging versus commit, process-crash recovery, deterministic full roots including replay state, canonical transaction bytes, grant/fence behavior, and explicit unsupported-query errors were exercised.

## Critical unassessed gate

The runtime could not reach the Go module proxy. `go install` and upstream wire probe dependency resolution failed. **No CometBFT engine was executed.** Do not call the scripted application-process harness a blockchain, validator network or consensus proof.

## Next actions, in order

1. In a network-enabled Linux/WSL build environment, run `bash scripts/verify_network.sh` without modifying pass criteria. Review the upstream wire probe first; then the four actual validator integration.
2. Fix any genuine ABCI/config/handshake incompatibilities, add regression tests, capture engine binary metadata and all raw gate output. In particular verify CometBFT crash recovery, stale node replay, 3-of-4 progress, 2-of-4 halt and resumed progress. The runner currently authors these checks; they are not observed successes.
3. Extend fault injection to engine/app crash-order permutations and node network partitions. Add independent commit/validator-signature verification, not just RPC agreement.
4. Select the final chain engine through explicit comparison. This adapter target is an integration route, not a claim the full architecture decision is final.
5. Replace full snapshot cloning with an authenticated, bounded-cost state store. Specify account registration, fee economics, denial-of-service bounds, signer custody and owner recovery. Keep failed-payment liabilities and external settlement isolated until a deliberate integration protocol exists.
6. Publish a dedicated private repository when an actual create route or exact new repository is available. Do not overwrite or repurpose unrelated repositories to work around missing create permissions.

## Entrypoints

`src/block_application.py`; `src/abci_wire.py`; `src/abci_server.py`; `scripts/check_abci_processes.py`; `scripts/run_devnet.py`; `tools/upstream-wireprobe/`; `docs/ABCI_INTEGRATION.md`; `docs/VERIFICATION.md`.

## Keep these invariants

A model never approves its own spending expansion. Delegation must not multiply authority. Pending is not settled. A restarted operation must reconcile before retrying a payment. Receipt-based replay state belongs in the state commitment. Only committed state is query-visible. No fake proof, fake reserve, fake partner, fake validator independence or unsupported performance claim.

ABCI is privileged and must not be given to agents. All current quantities and generated keys are fixtures. The 100 DEV test supply is not public tokenomics, a premine or a price. The account design is not a bank charter. Market price is not guaranteed by software.
