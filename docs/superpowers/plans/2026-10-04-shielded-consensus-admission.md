# Shielded Consensus Admission Implementation Plan

> **For agentic workers:** Use `dispatching-parallel-agents` for genuinely independent tasks or `executing-plans` for inline task-by-task execution. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement and qualify Protocol 5 as a fresh, finite, four-validator shielded-payment consensus profile with an actual Halo2 verifier, deterministic admission, atomic persistence, marker-only state sync, and source-bound real-engine evidence.

**Architecture:** A standalone Rust crate owns canonical cryptographic encodings, H2F, Poseidon, the note tree, the new Halo2 circuit, proof creation, proof verification, profile artifacts, KAT, and a confined verifier worker. Dedicated Python `protocol5_*` modules own consensus ordering, historical-root admission, budgets, deterministic state, SQLite durability, ABCI, state sync, certificate verification, and qualification runners. Only an external controller invokes the development prover; validator processes receive transaction wires and never receive witnesses or prover capability.

**Tech Stack:** Rust 1.97.1; `halo2_proofs` 0.4.0 with default features disabled; `pasta_curves` 0.6.0; `rand` 0.10.0; raw x86_64 Linux seccomp via `libc` 0.2.189; Python 3.12 standard library and SQLite; CometBFT 0.38.25; ABCI v0.38.25 protobuf.

**Spec:** `docs/superpowers/specs/2026-10-04-shielded-consensus-admission-design.md` at compatibility-amendment commit `60b2457`.

## Global Constraints

- Preserve Protocol 4 and `tools/privacy-proof-benchmark` byte-for-byte. Before every implementation commit run:
  ```bash
  test "$(git rev-parse HEAD:tools/privacy-proof-benchmark)" = "$(git rev-parse 013385c:tools/privacy-proof-benchmark)"
  test -z "$(git status --porcelain -- tools/privacy-proof-benchmark)"
  ```
- Freeze the chain ID ceiling at 50 printable ASCII bytes, matching CometBFT 0.38.25 genesis and header validation.
- Use a fresh Protocol 5 genesis and dedicated `protocol5_*` modules. Do not modify Protocol 4 application, state sync, database, AppHash, dispatcher, snapshot, or proof identities.
- Keep `1soft/privacy-proof-benchmark/halo2-pasta/v1` unchanged. The new circuit ID is `1soft/shielded-consensus/halo2-pasta/v1`.
- Rust owns all field, Poseidon, tree, commitment, nullifier, authorization, proof, profile, and KAT operations. Python consumes frozen vectors and calls the Rust worker.
- The worker has only Profile, TreeRootV1, VerifyProofV1, and VerifyAndAppendV1. It contains no witness or prover operation.
- Use `CARGO_TARGET_DIR=/home/xnuonux/1soft-phase7-cargo-target`.
- Use `/home/xnuonux/1soft-v016-execution/integrated/.venv/bin/python -B`.
- Run worker and development-prover Cargo suites separately. Never use `--all-features`.
- Keep cryptographic review, anonymity, network-metadata privacy, custody, public-network, exchange, and real-funds claims false.
- Preserve raw failures. Missing exact pinned inputs produce `unassessed`, never a synthetic pass.
- Keep witnesses and unredacted process evidence outside tracked public artifacts.
- Each task starts with the named failing test, reaches its GREEN command, runs the preservation check, and commits only owned files.

## File Map

- Rust: `tools/shielded-consensus/halo2/Cargo.toml`, `Cargo.lock`, all new `src` Rust modules/binaries, and all new Rust tests.
- Profile: `tools/shielded-consensus/profile/{public-schema-v1,profile-manifest-v1,sandbox-policy-v1,toolchain-manifest-v1}.json`, `profile-descriptor-v1.bin`, and `kat-v1.bin`.
- Vectors: `tools/shielded-consensus/test-vectors/crypto-v1.json`.
- Python: `src/protocol5_{encoding,worker,state,abci_wire,application,abci_server,state_sync,certificate}.py`.
- Scripts: `scripts/serve_abci_p5.py`, `serve_abci_p5_test.py`, `run_protocol5_engine.py`, and `run_protocol5_state_sync.py`.
- Tests: `tests/protocol5_fixture.py`, `shielded_worker_fixture.py`, and all `tests/test_protocol5_*.py`.
- Release/docs: `tools/shielded-consensus/{README.md,COMPONENT_MANIFEST.json,DEPENDENCY_RECEIPT.json}`, `tools/release/check_protocol5.py`, its gate tests, `docs/PROTOCOL5_SHIELDED_CONSENSUS.md`, `docs/ABCI_INTEGRATION.md`, `docs/ROADMAP.md`, `README.md`, and `SOURCE_MANIFEST.json`.

---

### Task 1: Canonical Rust encodings

**Files:** Create crate files, `src/{lib,constants,field,encoding}.rs`, schema/vector files, and `tests/encoding_vectors.rs`.

- [ ] Write `field_codec_and_h2f_match_frozen_vectors`; reject noncanonical fields and require H2F(`asset`,`1soft`) = `4b07fced1905ae36bdde8ef3e2a8ffc948e2d28739df96b5c260415ef894f435`.
- [ ] Test complete consumption for ProfileDescriptorV1, DeploymentBindingV1, KatV1, TransactionV1, WitnessV1, and frames. Assert WitnessV1 = 480 bytes and transaction prefix = 534 bytes.
- [ ] RED:
  ```bash
  CARGO_NET_OFFLINE=true RUSTUP_TOOLCHAIN=1.97.1 CARGO_TARGET_DIR=/home/xnuonux/1soft-phase7-cargo-target cargo test --locked --offline --no-default-features --manifest-path tools/shielded-consensus/halo2/Cargo.toml --test encoding_vectors field_codec_and_h2f_match_frozen_vectors -- --exact
  ```
- [ ] Implement canonical little-endian fields, SHA-512 H2F modulo the Pallas base modulus, exact bounded codecs, and offline lockfile.
- [ ] Pin `halo2_proofs = { version = "=0.4.0", default-features = false }`; use empty defaults, `worker = ["dep:libc"]`, and `dev-prover = ["dep:rand"]`.
- [ ] GREEN: run the complete encoding test binary and preservation checks.
- [ ] Commit `feat(shielded-consensus): freeze canonical Rust encodings`.

### Task 2: Native relation and note tree

**Files:** Create `src/{tree,relation,fixture}.rs`, `tests/{tree_vectors,native_relation}.rs`, and extend vectors.

- [ ] Test empty roots levels 0-4, roots for counts 0-16, output order, capacity, position-bound nullifiers, authorization, conservation, intervals, nonzero commitments, and distinct outputs.
- [ ] RED:
  ```bash
  CARGO_NET_OFFLINE=true RUSTUP_TOOLCHAIN=1.97.1 CARGO_TARGET_DIR=/home/xnuonux/1soft-phase7-cargo-target cargo test --locked --offline --no-default-features --manifest-path tools/shielded-consensus/halo2/Cargo.toml --test tree_vectors empty_and_append_roots_match_frozen_vectors -- --exact
  ```
- [ ] Implement Poseidon domains 100, 101, 102, 103, 105, and 106; the depth-4 capacity-16 tree; exact two-output append; and the fourteen-field native relation.
- [ ] GREEN: run both native test binaries and preservation checks.
- [ ] Commit `feat(shielded-consensus): implement native relation and note tree`.

### Task 3: Protocol 5 Halo2 circuit

**Files:** Create `src/circuit.rs` and `tests/circuit_relation.rs`.

- [ ] Write a one-mutation-at-a-time rejection matrix covering paths, positions, balance, authorization, nullifier, equal bounds, `u64::MAX`, wrap attempts, zero commitments, equal outputs, and both validity boundaries.
- [ ] RED:
  ```bash
  CARGO_NET_OFFLINE=true RUSTUP_TOOLCHAIN=1.97.1 CARGO_TARGET_DIR=/home/xnuonux/1soft-phase7-cargo-target cargo test --locked --offline --no-default-features --manifest-path tools/shielded-consensus/halo2/Cargo.toml --test circuit_relation rejects_interval_wrap_and_zero_commitments -- --exact
  ```
- [ ] Implement 64-bit ranges, `valid_until - valid_from - 1`, all interval differences, membership, position-bound nullifier, authorization, conservation, nonzero checks, and output inequality.
- [ ] GREEN: every valid fixture satisfies MockProver and every isolated mutation fails.
- [ ] Commit `feat(shielded-consensus): constrain the Protocol 5 Halo2 relation`.

### Task 4: Profile, KAT, verifier, and development prover

**Files:** Create `src/{verifier,prover,profile}.rs`, profile-builder/prover binaries, profile artifacts, and `tests/{proof_profile_kat,development_prover}.rs`.

- [ ] Test K=13, proof length under 60 KiB and fixed across several randomized valid witnesses, KAT success, prescribed mutation failure, and two different fresh valid proofs for one witness.
- [ ] RED:
  ```bash
  CARGO_NET_OFFLINE=true RUSTUP_TOOLCHAIN=1.97.1 CARGO_TARGET_DIR=/home/xnuonux/1soft-phase7-cargo-target cargo test --locked --offline --no-default-features --features dev-prover --manifest-path tools/shielded-consensus/halo2/Cargo.toml --test proof_profile_kat generated_profile_qualifies_k13_and_kat -- --exact
  ```
- [ ] Build `Params::new(13)`, VK, parameter hash, pinned-VK binding, profile ID, deterministic seeded KAT, and exact proof length.
- [ ] Use a closed source digest excluding generated descriptor/KAT. Keep profile manifest free of descriptor hash and worker self-hash.
- [ ] Define ProverRequestV1 as magic `1SFTPRV1`, identities/header fields, and exact 480-byte witness. Reject malformed/trailing input.
- [ ] Use OS randomness for live proofs; emit only TransactionV1.
- [ ] GREEN: regenerate profile/KAT twice byte-identically and run both test binaries.
- [ ] Commit `feat(shielded-consensus): freeze the Halo2 profile and KAT`.

### Task 5: Worker protocol and Linux confinement

**Files:** Create `src/{worker_protocol,sandbox_linux}.rs`, worker binary, and `tests/{worker_protocol,worker_process,sandbox_linux}.rs`.

- [ ] Test all four opcodes, exact frames, increasing nonzero IDs, complete consumption, profile echo, 16-leaf/1 MiB limits, InvalidStatement, InvalidProof, fatal InternalFailure, startup KAT, and absence of prover/witness operations.
- [ ] Test one thread, closed non-stdio FDs/stderr, `no_new_privs`, architecture check, and denial of all specified file/socket/process/exec/io_uring syscalls.
- [ ] RED:
  ```bash
  CARGO_NET_OFFLINE=true RUSTUP_TOOLCHAIN=1.97.1 CARGO_TARGET_DIR=/home/xnuonux/1soft-phase7-cargo-target cargo test --locked --offline --no-default-features --features worker --manifest-path tools/shielded-consensus/halo2/Cargo.toml --test worker_protocol profile_tree_verify_and_append_round_trip -- --exact
  ```
- [ ] Implement the four operations. VerifyAndAppend recomputes current `root_before` but accepts a separately validated historical anchor.
- [ ] Only canonical statement errors and Halo2 proof failures are deterministic. Terminate after framing, identity, internal-root, panic, or response failures.
- [ ] Construct Params/VK and verify KAT before confinement; then close FDs, apply `no_new_privs`, install x86_64 seccomp, and run denial probes.
- [ ] GREEN: run worker and dev-prover suites separately with one test thread; build release binaries.
- [ ] Commit `feat(shielded-consensus): confine the verifier worker`.

### Task 6: Python identities and quarantining worker client

**Files:** Create `src/protocol5_{encoding,worker}.py`, fixtures, and `tests/test_protocol5_{encoding,worker}.py`.

- [ ] Test Rust vectors, identity DAGs, canonical JSON, public-key-sorted four-validator genesis, cross-limit arithmetic, and separate CometBFT validator ordering.
- [ ] Test no-symlink worker opening, ownership/mode/hash/device/inode, `/proc/self/fd` launch, 120s startup/30s request watchdogs, increasing IDs, startup bindings, and permanent quarantine.
- [ ] Require one non-skipped test against the actual release worker and KAT.
- [ ] RED:
  ```bash
  ONE_P5_WORKER=/home/xnuonux/1soft-phase7-cargo-target/release/shielded-verifier-worker ONE_P5_PROFILE="$PWD/tools/shielded-consensus/profile/profile-descriptor-v1.bin" ONE_P5_KAT="$PWD/tools/shielded-consensus/profile/kat-v1.bin" PYTHONPATH=src:tests /home/xnuonux/1soft-v016-execution/integrated/.venv/bin/python -B -m unittest test_protocol5_encoding.Protocol5EncodingTests.test_identity_dag_and_golden_vectors test_protocol5_worker.Protocol5WorkerTests.test_startup_binds_profile_deployment_kat
  ```
- [ ] Implement strict codecs without Python Poseidon/proofs and a serialized client where only InvalidStatement/InvalidProof return deterministic results.
- [ ] GREEN: run both modules and preservation checks.
- [ ] Commit `feat(protocol5): freeze identities and quarantine verifier worker`.

### Task 7: Deterministic state and budgets

**Files:** Create `src/protocol5_state.py` and `tests/test_protocol5_state.py`.

- [ ] Use actual proofs to test two same-root spends, frozen block-start anchors, sequential appends, duplicates, validity, fee overflow, accepted/tree/fee limits, and retained-entry/byte limits.
- [ ] Assert accepted/history counters and raw byte totals exactly.
- [ ] RED:
  ```bash
  ONE_P5_WORKER=/home/xnuonux/1soft-phase7-cargo-target/release/shielded-verifier-worker ONE_P5_PROVER=/home/xnuonux/1soft-phase7-cargo-target/release/shielded-development-prover PYTHONPATH=src:tests /home/xnuonux/1soft-v016-execution/integrated/.venv/bin/python -B -m unittest test_protocol5_state.Protocol5StateTests.test_same_root_spends_and_global_conflicts
  ```
- [ ] Implement closed state/AppHash, roots, receipts, execution blocks, speculative state, result precedence, and real worker calls.
- [ ] Enforce global history budget: CheckTx code 7, Prepare stops, Process rejects, Finalize aborts before pending state.
- [ ] GREEN: run the full module and preservation checks.
- [ ] Commit `feat(protocol5): implement deterministic shielded state transitions`.

### Task 8: Atomic application, ABCI, and hostile boundaries

**Files:** Create `src/protocol5_{abci_wire,application,abci_server}.py`, `scripts/serve_abci_p5.py`, and application/hostile/ABCI tests.

- [ ] Test open audit, InitChain, CheckTx, Prepare/Process/Finalize, no-op Commit, queries, exact replay, wrong-request refusal, height-one empty commit, later complete roster/flags, greater-than-two-thirds flag-2 power, and immutable next-validator hash at every height.
- [ ] Test run-token process exits immediately before/after the one SQLite commit, same-store restart, exact replay, and no duplicate state effect.
- [ ] RED:
  ```bash
  ONE_P5_WORKER=/home/xnuonux/1soft-phase7-cargo-target/release/shielded-verifier-worker ONE_P5_PROVER=/home/xnuonux/1soft-phase7-cargo-target/release/shielded-development-prover PYTHONPATH=src:tests /home/xnuonux/1soft-v016-execution/integrated/.venv/bin/python -B -m unittest test_protocol5_application.Protocol5ApplicationTests.test_finalize_commit_is_atomic_and_replay_exact
  ```
- [ ] Create P5-only committed, blocks, history, and marker tables. Persist checkpoint/response/replay/history/marker deletion in one `BEGIN IMMEDIATE`; pending state is memory-only.
- [ ] Reuse only generic `abci_server.Server` and descriptor primitives.
- [ ] GREEN: run application, hostile-boundary, and ABCI modules.
- [ ] Commit `feat(protocol5): add atomic shielded ABCI application`.

### Task 9: Marker-only state sync

**Files:** Create `src/protocol5_state_sync.py` and `tests/test_protocol5_state_sync.py`.

- [ ] Test canonical payload, 64 KiB chunks, 128-chunk/8 MiB limits, duplicate/out-of-order behavior, exact same-height recovery, fork refusal, newer replacement, lost-final-reply reoffer, first post-sync marker deletion, rollback, and every payload mutation.
- [ ] RED:
  ```bash
  ONE_P5_WORKER=/home/xnuonux/1soft-phase7-cargo-target/release/shielded-verifier-worker ONE_P5_PROVER=/home/xnuonux/1soft-phase7-cargo-target/release/shielded-development-prover PYTHONPATH=src:tests /home/xnuonux/1soft-v016-execution/integrated/.venv/bin/python -B -m unittest test_protocol5_state_sync.Protocol5StateSyncTests.test_marker_only_replay_reoffer_and_continue
  ```
- [ ] Replay every execution block through the real worker before install. Install state, tx history, and exactly one marker; install no historical Comet response/hash rows.
- [ ] Same-height requires exact marker/genesis/profile/deployment/AppHash/payload hash. Retain one volatile completed-offer result for reoffer.
- [ ] GREEN: run module and preservation checks.
- [ ] Commit `feat(protocol5): add verifier-replayed marker-only state sync`.

### Task 10: Certificates, release checker, and runners

**Files:** Create `src/protocol5_certificate.py`, component/dependency manifests, `tools/release/check_protocol5.py`, gate tests, test server, both runners, and runner tests.

- [ ] Test a P5 trust anchor and signed header without broadening legacy `trust_from_genesis`.
- [ ] Test changed/missing engine, worker, prover, profile, KAT, policy, toolchain, source, scenarios, process receipts, and public-data leakage.
- [ ] Test output preservation, owned cleanup, run-token fault hooks, worker PID observation, and `unassessed` on missing pins.
- [ ] RED:
  ```bash
  PYTHONPATH=src:tests:scripts:tools/release /home/xnuonux/1soft-v016-execution/integrated/.venv/bin/python -B -m unittest test_protocol5_certificate test_protocol5_gate test_protocol5_engine_runner test_protocol5_state_sync_runner
  ```
- [ ] Implement four fresh equal-power validators, actual proofs from controller only, all specified admission/restart/worker-failure cases, signed-header verification, convergence, leakage scan, and redacted public projection.
- [ ] Implement real state sync with a never-started nonvalidator, hostile chunk/offers, final-Apply crash, observed Comet reoffer, marker recovery, post-sync transaction, and convergence.
- [ ] GREEN: all runner/gate unit modules pass; preservation checks pass.
- [ ] Commit `test(protocol5): add source-bound engine and state-sync qualification`.

### Task 11: Execute source-bound qualification and repair failures

- [ ] Build release worker and prover separately in the external target directory.
- [ ] Run all Rust worker tests, all Rust dev-prover tests, and all Protocol 5 Python modules against exact release binaries.
- [ ] Run every Protocol 4 Python test and the old Halo2 verifier into fresh external reports.
- [ ] Run both Protocol 5 real-engine scripts into fresh private/public directories and validate them with `check_protocol5.py`.
- [ ] For each failure, preserve raw evidence, add the smallest detecting regression, repair the root cause, rerun the narrow gate, then rerun the affected source-bound gate.
- [ ] Continue only when both real-engine runners pass or an exact unavailable input is truthfully `unassessed`.

### Task 12: Register the qualified source

**Files:** Create component README and Protocol 5 guide; update manifests, integration guide, roadmap, root README, and `SOURCE_MANIFEST.json`.

- [ ] Document limits, identities, confinement, regeneration, controller-only prover, launch/query/state-sync/recovery, evidence paths, and one-host boundary.
- [ ] Record spec/implementation commit/tree, exact binary/profile/genesis/deployment/toolchain/policy hashes, reports, negative observations, and all false production claims.
- [ ] Add every new source/test/script/profile/vector/doc to `SOURCE_MANIFEST.json`.
- [ ] Scan for unfinished placeholder markers, omitted scenarios, and fabricated production language.
- [ ] Run `/home/xnuonux/1soft-v016-execution/integrated/.venv/bin/python -B scripts/run_tests.py`.
- [ ] Validate both public receipts, run preservation checks, and review the full diff against `013385c`.
- [ ] Commit `docs(protocol5): bind qualified source and finite-chain evidence`.
- [ ] Verify a clean tree and merge only the reviewed commits into the authorized integration branch.
