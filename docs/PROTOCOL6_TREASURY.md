# Protocol 6: atomic private treasury through validators

P6 is a separate fresh-genesis development protocol for agent-controlled treasury payments. One frozen Halo2 proof binds value conservation, a merchant note, restricted change and both parent/grant allowance debits. Four local CometBFT validators order that combined transition; state H can be authenticated through their signed H+1 header. P1-P5 remain separate and unchanged.

## Exact scope

The immutable genesis pins the entire initial treasury, four equal-power validator keys, epoch, fee, proof profile, known-answer proof and verifier binary. Parent and grant spending commitments advance only through the combined proof. Grant IDs and the epoch are static. There is no revocation, rotation, enrollment, minting, redemption, wallet obligation release or snapshot installation route. The old lab's unsigned local revoke function is never exposed to validators.

The first runner uses public synthetic treasury domain 700 and two synthetic restricted inputs of 10 units each. The shared parent allowance is 10; each initial grant permits 8. An initial payment of 4 plus fee 2 consumes 6 of the shared allowance. Only one of two competing initial proofs can commit. A separately prepared 2-unit payment plus fee 2 uses the remaining 4. This is an execution fixture, not a token issuance or economic-value demonstration. Refreshed fixture feasibility does not authorize replacing an uncertain wallet obligation.

Transactions are exactly 4008 bytes: the frozen 25-field statement plus a 3200-byte Halo2 proof. K14, Pasta IPA, Poseidon domains and parameter/VK fingerprints match the original atomic treasury component. P6 has distinct transaction, finalization and AppHash domains. Exact current parent/grant/context authority is required; historical admitted value-note roots are allowed. Receipts commit raw bytes, the entire public statement, note/authority roots, positions, nullifiers, fee and execution position.

## Execution and recovery

CheckTx reserves nothing. PrepareProposal filters candidates through isolated ordered execution; ProcessProposal rejects conflicts or any invalid transaction. FinalizeBlock stages an exact response without exposing pending state. Commit writes checkpoint state and block/response/request-wire identity together in FULL-sync SQLite WAL. Restart reconstructs all treasury state and receipts from retained transactions and recomputes each retained finalization identity, including its durable request bytes. SQL write failure or process death leaves either the complete old checkpoint or complete new one.

There are 64 heights, two transactions per block, eight inspected candidates, 64 retained transactions, 16 notes, at most seven successful payments and a 256KiB canonical state ceiling. This finite profile deliberately stops when its budgets are exhausted. It is not a scalable pool or long-term network state design.

The P6 Rust bridge contains verification and root operations only. It creates parameters and a verifying key, checks their frozen hashes, and consumes the entire proof transcript. It does not generate a proving key. A pinned open executable inode crosses into a child-only resource-limited launcher: 30 CPU seconds, 2GiB address space, 256-byte regular-file stdout/stderr limits, no core files, 32 descriptors and a 45-second wall deadline per call. Invalid proof is a normal reject; unavailable/profile/binary/resource/output failure aborts the application. This is a trusted-host subprocess, not the P5 seccomp worker or public-node isolation. Verification startup cost remains significant; the loopback client submission deadline is 60 seconds, with no automatic resend. In the owned test-node configuration, timeout_broadcast_tx_commit is 50 seconds. The inspected CometBFT 0.38.25 node.go sets global HTTP WriteTimeout to that configured value plus one second; the default 10-second write limit otherwise closes a cold verification response. This is a bounded development configuration and does not relax payment expiry, proof or allowance checks.

## Reproduce and check

Use a clean saved Git checkout, Rust 1.97.1, cached locked dependencies, the exact CometBFT 0.38.25 binary and the public proof fixtures delivered with the evidence. Missing dependencies are not a reason to use mock proofs.

```sh
cargo +1.97.1 build --manifest-path tools/treasury-consensus-bridge/Cargo.toml --release --locked --offline --target-dir /absolute/fresh-target
python scripts/run_protocol6_engine.py --engine /absolute/cometbft --worker /absolute/fresh-target/release/treasury-consensus-bridge --fixtures /absolute/public-fixtures --output /absolute/fresh-evidence.json
python tools/release/check_protocol6.py /absolute/fresh-evidence.json
```

The manifest-checked default Python suite reports real-P6 tests as unassessed skips when P6_WORKER/P6_WORKER_SHA256 or P6_REPORT are not explicitly supplied. Qualification runs require these real inputs and no skipped P6 checks. Missing engine, worker or public fixtures returns an unassessed report with no process launch; malformed supplied inputs fail.

The runner uses the unchanged earlier harness only for owned process/RPC mechanics; it selects new P6 genesis, application, verification and certificates. It never starts the non-validator state-sync target. Its candidate mode labels dirty exploratory execution as candidate-passed and cannot pass the qualification checker. Final evidence binds the clean implementation commit/tree, runtime source byte hashes, binary and fixture identities, explicit startup KAT receipts, all 18 checks, actual process exits, sanitized raw engine/application logs and the signed full-state witness. The checker requires the captured implementation Git objects and matching current runtime sources. A plain extracted source ZIP alone does not supply those Git objects.

The local reports and logs are unsigned artifacts. Joint fabrication of a report, logs and hashes is outside their provenance guarantee. The validator signatures authenticate AS-OF state under the pinned static-quorum assumption; they do not establish freshness, independent operators, independent rule replay, production consensus security, cryptographic audit, metadata privacy, custody, external settlement or real-funds readiness.

## Next integration boundary

An authenticated owner lifecycle and certified wallet obligations must be designed before this can safely become an agent payment product. Merchant note discovery, disclosure and redemption are also separate unfinished capabilities. No existing P5 wallet or local outbox is silently upgraded by this protocol.

## Recorded qualification

The [real-engine report](../evidence/protocol6-treasury/20261004/engine-qualified-01.json) captures clean implementation commit `175f9f3f20f291befad6bbfd2e3d478ddecf3a5d`, tree `36bb8a73196a6c15d46d4089ecd77d9ba50c0285`. Its 18 checks passed. The signed height-20 header authenticates state height 19 under 30/40 static-genesis voting power. The [AI review and validation record](../evidence/protocol6-treasury/20261004/AI_REVIEW.md) describes tested recovery and timeout repairs and separates actual proof tests from optional default-suite skips. Registration commits add only documentation, manifests and evidence; qualified runtime bytes remain unchanged.
