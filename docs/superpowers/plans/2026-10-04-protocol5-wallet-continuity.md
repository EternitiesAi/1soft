# Protocol 5 Wallet Continuity Implementation Plan

> **For agentic workers:** Use `dispatching-parallel-agents` for genuinely independent tasks or `executing-plans` for inline task-by-task execution. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and source-qualify a finite, trusted-host Protocol 5 development wallet that pays a public recipient owner key, durably preserves exact proved transactions and unresolved obligations, authenticates full bounded state with the signed H+1 header, hands one selected output to its owner through `NoteCapsuleV1`, and submits each decision at most once through one local delivery journal.

**Architecture:** Protocol 5 consensus, TransactionV1, the Halo2 relation, profile, KAT, verifier worker, genesis, and finite state model remain unchanged. Three additive controller-only Rust opcodes derive an owner key, build the existing ProverRequestV1 with public recipient keys, and derive a position-bound note nullifier without constructing a spend; Python owns the bounded subprocess adapter, private note capsule, append-only SQLite wallet/delivery journals, H+1 state observation, CLI, and source-bound real-engine gate. The chain contains commitments but no encrypted note payload, so this phase imports an explicitly handed-off private capsule and scans only for known commitments; it does not claim automatic chain discovery.

**Tech Stack:** Rust 1.97.1; the existing locked `shielded-consensus-halo2` crate with `halo2_proofs` 0.4.0/default features off; Python 3.12 standard library and SQLite; CometBFT 0.38.25; the existing Protocol 5 profile, KAT, zero-argument verifier worker, TransactionV1, and state-certificate verifier.

**Spec:** `docs/PRIVATE_ECONOMIC_AUTHORITY_DIRECTION.md`, especially the durable-obligation and reuse boundaries; `docs/PROTOCOL5_SHIELDED_CONSENSUS.md`; and `docs/superpowers/specs/2026-10-04-shielded-consensus-admission-design.md`. This phase implements the wallet prerequisite only. It does not implement the later shared-authority relation.

## Global Constraints

- Start from merged main commit `fb2316b2ecdf1c647ca0fc34fa04db78077e3b24`. Work only in an isolated branch/worktree. Do not reset, force-push, or overwrite another worker's files.
- Preserve Protocols 1-4, Protocol 5 consensus, TransactionV1, WitnessV1, the fourteen public fields, circuit/profile/KAT identities, the worker protocol, state sync, and `tools/privacy-proof-benchmark` byte-for-byte. The only existing Rust source allowed to change is `tools/shielded-consensus/halo2/src/development_client.rs` and its controller-only test.
- Preserve request opcodes 1 (`GenesisCommitments`) and 2 (`Spend`) and every byte they currently encode. Add opcode 3 (`DeriveOwnerKey`), opcode 4 (`SpendToRecipientKeys`), and opcode 5 (`DeriveNoteNullifier`) under client version 1. Do not add a worker opcode, witness operation, or prover operation.
- Keep `MAX_CLIENT_REQUEST_BYTES == 1966`. Opcode 3 is 44 bytes. Opcode 4 replaces each output `owner_spend_secret` with an equally sized canonical `owner_key`, so its request bound is unchanged. Opcode 5 is 270 bytes and returns one 42-byte position-bound nullifier. All three require complete consumption and reject malformed, noncanonical, zero, excessive, and trailing input.
- Keep the existing ProverRequestV1 exactly 1,010 bytes, WitnessV1 exactly 480 bytes, TransactionV1 prefix exactly 534 bytes, and qualified proof length exactly 3,136 bytes.
- Rust remains the sole implementation of SpendKey, Poseidon note commitments, authentication paths, nullifiers, public fields, and proof generation. Python only validates canonical fields, encodes frozen controller wires, invokes Rust through stdin, and parses exact responses.
- Keep client and prover controller-only. Validator homes, commands, environment, ABCI traffic, databases, snapshots, receipts, and logs must never contain their paths, witness bytes, ProverRequestV1, spend secrets, note secrets, or blindings.
- `NoteCapsuleV1` is an explicit private handoff for one known note. There is no on-chain ciphertext, incoming viewing key, automatic public-chain scan, anonymous transport, or production custody claim.
- Store only synthetic DEV secrets. Use a trusted local POSIX directory, refuse symlinks and unsafe ownership/mode, create databases and secret outputs with mode `0600`, use SQLite WAL plus `synchronous=FULL`, and describe hostile-host rollback and copied-journal coordination as out of scope.
- Preparing a spend has no financial effect and invokes neither client nor prover. Approval may invoke both, but it must atomically persist the exact TransactionV1, input hold, review, and both private output openings before returning any transaction bytes.
- A lost approval return recovers the exact stored TransactionV1 without invoking the prover. Expiry, CheckTx decline, missing receipt, another transaction winning the nullifier, or process failure never silently releases or erases the obligation.
- A delivery attempt is committed before network I/O. No automatic retry, reset, cancel, arbitrary-transaction submission, or second-journal fallback is exposed. Endpoint admission is an observation, not execution evidence. Collection and wallet reconciliation remain separate.
- Wallet state changes require a canonical `/state` witness authenticated by the exact signed header at `state_height + 1` through `verify_protocol5_state_certificate`. Peer metadata, CheckTx, mempool presence, RPC success, and an unsigned query are not authority.
- Use explicit loopback endpoints of the form `http://127.0.0.1:PORT/`. Do not use DNS, redirects, proxies, public RPCs, public deployment, real funds, production keys, paid compute, or GitHub Actions.
- Use separate targets throughout:
  ```bash
  export PHASE8_BASE=fb2316b2ecdf1c647ca0fc34fa04db78077e3b24
  export P8_WORKER_TARGET=/home/xnuonux/1soft-phase8-worker-target
  export P8_DEV_TARGET=/home/xnuonux/1soft-phase8-dev-target
  export P8_EVIDENCE=/home/xnuonux/1soft-phase8-evidence
  export P8_PRIVATE=/home/xnuonux/1soft-phase8-private
  export P8_PYTHON=/home/xnuonux/1soft-v016-execution/integrated/.venv/bin/python
  export CARGO_NET_OFFLINE=true
  ```
- Never use Cargo `--all-features`. Run worker and `dev-prover` tests/builds in separate commands and separate target directories.
- Every completed evidence report keeps these claims false: production readiness/security/privacy/custody, anonymity, network-metadata privacy, automatic note discovery, hostile-host rollback resistance, cross-device coordination, independent cryptographic/security review, multi-host Byzantine qualification, public-network/exchange readiness, real-funds safety, and economic value.
- Missing exact engine, worker, client, prover, profile, KAT, policy, toolchain, genesis, or source inputs yields a truthful `unassessed` report. Do not substitute a fixture and call the result real-engine evidence.

Before every implementation commit, run this path-preservation gate from the repository root. It permits only the complete Phase 8 ownership set and rejects tracked or untracked drift elsewhere:

```bash
$P8_PYTHON -B - <<'PY'
import subprocess

base = "fb2316b2ecdf1c647ca0fc34fa04db78077e3b24"
exact = {
    "README.md", "SOURCE_MANIFEST.json", "docs/ABCI_INTEGRATION.md",
    "docs/PROTOCOL5_SHIELDED_CONSENSUS.md", "docs/PROTOCOL5_WALLET_CONTINUITY.md",
    "docs/ROADMAP.md",
    "docs/superpowers/plans/2026-10-04-protocol5-wallet-continuity.md",
    "docs/superpowers/specs/2026-10-04-protocol5-wallet-continuity-design.md",
    "reference/protocol5-wallet-qualification-settings-v1.json",
    "scripts/protocol5_wallet.py", "scripts/read_protocol5_state.py",
    "scripts/run_protocol5_engine.py", "scripts/run_protocol5_wallet_engine.py",
    "src/protocol5_controller.py", "src/protocol5_delivery.py",
    "src/protocol5_note_capsule.py", "src/protocol5_state_reader.py",
    "src/protocol5_transport.py", "src/protocol5_wallet.py",
    "tests/test_protocol5_controller.py", "tests/test_protocol5_delivery.py",
    "tests/test_protocol5_engine_runner.py", "tests/test_protocol5_note_capsule.py",
    "tests/test_protocol5_state_reader.py", "tests/test_protocol5_wallet.py",
    "tests/test_protocol5_transport.py",
    "tests/test_protocol5_wallet_cli.py", "tests/test_protocol5_wallet_gate.py",
    "tests/test_protocol5_wallet_runner.py",
    "tools/release/check_protocol5_wallet.py",
    "tools/shielded-consensus/README.md",
    "tools/shielded-consensus/halo2/src/development_client.rs",
    "tools/shielded-consensus/halo2/tests/development_client.rs",
    "tools/shielded-consensus/test-vectors/wallet-client-v1.json",
}
prefixes = ("tools/protocol5-wallet/",)
changed = set(subprocess.check_output(
    ["git", "diff", "--name-only", base, "--"], text=True).splitlines())
for line in subprocess.check_output(
        ["git", "status", "--porcelain=v1"], text=True).splitlines():
    changed.add(line[3:])
bad = sorted(path for path in changed
             if path not in exact and not path.startswith(prefixes))
if bad:
    raise SystemExit("out-of-scope Phase 8 paths: " + ", ".join(bad))
PY

git diff --quiet "$PHASE8_BASE" --   tools/privacy-proof-benchmark tools/shielded-note-lab   tools/protocol4-wallet tools/protocol4-delivery   tools/shielded-consensus/profile   tools/shielded-consensus/test-vectors/crypto-v1.json   tools/shielded-consensus/halo2/Cargo.toml   tools/shielded-consensus/halo2/Cargo.lock   tools/shielded-consensus/halo2/src/bin   tools/shielded-consensus/halo2/src/circuit.rs   tools/shielded-consensus/halo2/src/constants.rs   tools/shielded-consensus/halo2/src/encoding.rs   tools/shielded-consensus/halo2/src/field.rs   tools/shielded-consensus/halo2/src/fixture.rs   tools/shielded-consensus/halo2/src/profile.rs   tools/shielded-consensus/halo2/src/prover.rs   tools/shielded-consensus/halo2/src/relation.rs   tools/shielded-consensus/halo2/src/sandbox_linux.rs   tools/shielded-consensus/halo2/src/tree.rs   tools/shielded-consensus/halo2/src/verifier.rs   tools/shielded-consensus/halo2/src/worker_protocol.rs   src/protocol5_abci_server.py src/protocol5_abci_wire.py   src/protocol5_application.py src/protocol5_certificate.py   src/protocol5_encoding.py src/protocol5_state.py   src/protocol5_state_sync.py src/protocol5_worker.py
```

## File Map

- Rust controller wire: modify `tools/shielded-consensus/halo2/src/development_client.rs` and `tools/shielded-consensus/halo2/tests/development_client.rs`; add `tools/shielded-consensus/test-vectors/wallet-client-v1.json`.
- Shared Python controller: add `src/protocol5_controller.py`; update `scripts/run_protocol5_engine.py` and its runner test to import the shared adapter without changing existing runner semantics.
- Private note handoff: add `src/protocol5_note_capsule.py` and `tests/test_protocol5_note_capsule.py`.
- Authenticated reads: add `src/protocol5_state_reader.py`, `scripts/read_protocol5_state.py`, and `tests/test_protocol5_state_reader.py`.
- Wallet: add `src/protocol5_wallet.py` and `tests/test_protocol5_wallet.py`.
- Delivery: add `src/protocol5_transport.py`, `src/protocol5_delivery.py`, `tests/test_protocol5_transport.py`, and `tests/test_protocol5_delivery.py`.
- Operator entrypoint: add `scripts/protocol5_wallet.py` and `tests/test_protocol5_wallet_cli.py`.
- Qualification: add `scripts/run_protocol5_wallet_engine.py`, `tools/release/check_protocol5_wallet.py`, `tests/test_protocol5_wallet_runner.py`, `tests/test_protocol5_wallet_gate.py`, and `reference/protocol5-wallet-qualification-settings-v1.json`.
- Registration: add `tools/protocol5-wallet/{README.md,COMPONENT_MANIFEST.json,DEPENDENCY_RECEIPT.json}` and `docs/PROTOCOL5_WALLET_CONTINUITY.md`; update root README, ROADMAP, P5 guide, ABCI guide, shielded-consensus README, and `SOURCE_MANIFEST.json`.

---

### Task 1: Add public-recipient controller opcodes without changing Protocol 5

**Files:**
- Modify: `tools/shielded-consensus/halo2/src/development_client.rs`
- Modify: `tools/shielded-consensus/halo2/tests/development_client.rs`
- Create: `tools/shielded-consensus/test-vectors/wallet-client-v1.json`

**Interfaces:**
- Consumes: existing `NoteDomainV1`, `SpendHeaderV1`, `NoteDefinitionV1`, `ProverRequestV1`, `spend_key`, `note_commitment`, tree functions, and opcodes 1/2.
- Produces:
  ```rust
  pub struct RecipientNoteDefinitionV1 {
      pub expiry: u64,
      pub value: u64,
      pub owner_key: FieldBytes,
      pub note_secret: FieldBytes,
      pub blinding: FieldBytes,
  }

  DevelopmentClientRequestV1::DeriveOwnerKey {
      spend_secret: FieldBytes,
  }

  DevelopmentClientRequestV1::SpendToRecipientKeys {
      genesis_sha256: Digest32,
      deployment_id: Digest32,
      header: SpendHeaderV1,
      commitments: Vec<FieldBytes>,
      input_position: u16,
      input_note: NoteDefinitionV1,
      outputs: [RecipientNoteDefinitionV1; 2],
  }

  pub struct OwnerKeyV1 { pub owner_key: FieldBytes }
  ```
- Exact wire: request opcode 3 is `1SFTCLI1 | u16 1 | u16 3 | 32-byte canonical nonzero spend_secret`; response is `1SFTKEY1 | u16 1 | 32-byte canonical nonzero owner_key`. Opcode 4 is byte-for-byte opcode 2 except the opcode is 4 and each output's third 32-byte field is already an owner key. Opcode 5 is `1SFTCLI1 | u16 1 | u16 5 | five domain fields | u16 position | commitment | spend_secret | note_secret`; response is `1SFTNUL1 | u16 1 | nullifier`.

- [ ] **Step 1: Freeze the old interface before editing.** Extend the current Rust test so its existing genesis/opcode-1 and spend/opcode-2 request bytes are hashed into `wallet-client-v1.json`; assert their lengths, headers, SHA-256 values, decoded values, and derived ProverRequestV1 remain fixed.
- [ ] **Step 2: Write failing tests** named `derive_owner_key_uses_frozen_spend_key_relation`, `public_recipient_spend_never_requires_recipient_secret`, `legacy_opcodes_remain_byte_identical`, and `new_opcodes_reject_zero_noncanonical_trailing_and_overbound_input`. The round trip must prove that recipient secret 43 is never present in the opcode-4 request, ProverRequestV1, or TransactionV1 while its frozen owner key is present in the witness only as `output_recipient_keys[0]`.
- [ ] **Step 3: Run the narrow RED gate.** Expected result is a compile failure because the new enum variants/types do not exist:
  ```bash
  CARGO_TARGET_DIR="$P8_DEV_TARGET" cargo +1.97.1 test --locked --offline     --no-default-features --features dev-prover     --manifest-path tools/shielded-consensus/halo2/Cargo.toml     --test development_client derive_owner_key_uses_frozen_spend_key_relation -- --exact
  ```
- [ ] **Step 4: Implement only the three controller opcodes.** Factor the common assignment builder so opcode 2 maps its two output secrets through `spend_key`, while opcode 4 decodes and uses its two canonical nonzero `owner_key` fields directly. Keep all input-note ownership checks, membership, conservation, validity, nonzero/distinct commitments, and `assignment.rebuild_derived()` unchanged.
- [ ] **Step 5: Implement `OwnerKeyV1::encode/decode` and `NoteNullifierV1::encode/decode`** with exact magic/version/length and complete consumption. Reject zero input secrets, commitments, owner keys, and nullifiers; do not log or format secret bytes in errors.
- [ ] **Step 6: Run GREEN and the complete dev-prover suite.**
  ```bash
  CARGO_TARGET_DIR="$P8_DEV_TARGET" cargo +1.97.1 test --locked --offline     --no-default-features --features dev-prover     --manifest-path tools/shielded-consensus/halo2/Cargo.toml -- --test-threads=1
  ```
- [ ] **Step 7: Run the path-preservation gate.** Confirm `Cargo.toml`, `Cargo.lock`, circuit/profile/KAT, prover, worker, and `crypto-v1.json` have no diff.
- [ ] **Step 8: Commit** `feat(protocol5-wallet): add public-recipient controller opcodes` with only the three task files.

### Task 2: Extract one bounded Python controller adapter

**Files:**
- Create: `src/protocol5_controller.py`
- Create: `tests/test_protocol5_controller.py`
- Modify: `scripts/run_protocol5_engine.py`
- Modify: `tests/test_protocol5_engine_runner.py`

**Interfaces:**
- Produces:
  ```python
  @dataclass(frozen=True)
  class SecretNote:
      expiry: int
      value: int
      owner_spend_secret: bytes
      note_secret: bytes
      blinding: bytes

  @dataclass(frozen=True)
  class RecipientOutput:
      expiry: int
      value: int
      owner_key: bytes
      note_secret: bytes
      blinding: bytes

  class DevelopmentController:
      def derive_owner_key(self, spend_secret: bytes) -> bytes: ...
      def commitments(self, notes: list[SecretNote]) -> tuple[list[str], str]: ...
      def spend_request(self, genesis_raw: bytes, commitments: list[str],
                        input_position: int, input_note: SecretNote,
                        output_notes: tuple[SecretNote, SecretNote], *,
                        valid_from: int, valid_until: int) -> bytes: ...
      def spend_to_recipient_keys(
          self, genesis_raw: bytes, commitments: list[str], input_position: int,
          input_note: SecretNote,
          outputs: tuple[RecipientOutput, RecipientOutput], *,
          valid_from: int, valid_until: int) -> bytes: ...
      def prove(self, genesis_raw: bytes, prover_request: bytes) -> bytes: ...
  ```
- `scripts/run_protocol5_engine.py` continues to export `Note`, `DevelopmentController`, and `development_note` so the state-sync runner and existing tests do not change import behavior.

- [ ] **Step 1: Write failing adapter tests.** Capture subprocess arguments/stdin; require zero extra argv, reduced `PATH`/`LC_ALL` environment, secrets only in stdin, separate 30-second client and 300-second prover elapsed watchdogs, bounded stdout/stderr while the child runs, empty stderr on success, request-buffer overwrite in `finally`, and fail-closed nonzero/trailing/malformed output. Add one actual-binary client→prover→TransactionV1 test guarded by required `ONE_P5_CLIENT` and `ONE_P5_PROVER` paths; it must not skip in the qualification command.
- [ ] **Step 2: Run RED.**
  ```bash
  PYTHONPATH=src:tests:scripts "$P8_PYTHON" -B -m unittest     test_protocol5_controller.Protocol5ControllerTests.test_public_recipient_wire_is_exact_and_stdin_only
  ```
- [ ] **Step 3: Move, do not duplicate,** the current `Note`, random-field helper, `DevelopmentController`, and wire constants out of `run_protocol5_engine.py`. Add opcode-3, opcode-4, and opcode-5 methods. Use `Transaction.decode` on every prover result. Do not import or reimplement Poseidon, tree, commitment, nullifier, or authorization logic in this module.
- [ ] **Step 4: Keep the old runner compatible.** Alias `SecretNote` as `Note`, import the shared controller, and rerun existing controller-wire tests unchanged except for import location. The old runner must still use opcode 1 for genesis and opcode 2 for its historical qualification scenarios.
- [ ] **Step 5: Run GREEN.**
  ```bash
  ONE_P5_CLIENT="$P8_DEV_TARGET/debug/shielded-development-client"   ONE_P5_PROVER="$P8_DEV_TARGET/debug/shielded-development-prover"   PYTHONPATH=src:tests:scripts "$P8_PYTHON" -B -m unittest     test_protocol5_controller test_protocol5_engine_runner
  ```
- [ ] **Step 6: Run preservation and commit** `refactor(protocol5): share the bounded controller adapter`.

### Task 3: Define and verify private NoteCapsuleV1

**Files:**
- Create: `src/protocol5_note_capsule.py`
- Create: `tests/test_protocol5_note_capsule.py`
- Create: `tools/protocol5-wallet/test-vectors/note-capsule-v1.json`

**Interfaces:**
- Produce `NOTE_CAPSULE_FORMAT = "1soft/protocol5-note-capsule/v1"`, `MAX_NOTE_CAPSULE_BYTES = 2048`, `capsule_id(value) -> str`, `decode_capsule(raw, genesis_raw) -> dict`, and `verify_capsule(raw, owner_spend_secret, authenticated_state, controller) -> dict`.
- Closed canonical keys are `format`, `version`, `capsule_id`, `genesis_sha256`, `profile_id`, `deployment_id`, `origin`, `commitment`, `owner_key`, `expiry`, `value`, `note_secret`, and `blinding`.
- `origin` is exactly `{"kind":"genesis","position":N}` or `{"kind":"transaction","txid":HEX64,"output_index":0|1}`; transaction output position is derived from the authenticated receipt, never trusted from the capsule.

- [ ] Write failing tests for both origin variants, duplicate/unknown/missing keys, bool/float integers, noncanonical JSON/hex/fields, zero values/secrets/keys, the 2,048-byte boundary, trailing bytes, wrong identities/owner secret/receipt/index/derived position/commitment, and one-field mutations.
- [ ] Require `verify_capsule` to call Rust opcode 3 `derive_owner_key` and existing opcode 1 one-note `commitments`; patch Python `h2f` to fail if called.
- [ ] RED:
  ```bash
  PYTHONPATH=src:tests:scripts "$P8_PYTHON" -B -m unittest     test_protocol5_note_capsule.Protocol5NoteCapsuleTests.test_transaction_capsule_requires_exact_authenticated_output
  ```
- [ ] Implement strict decoding. Accept a transaction capsule only when exactly one authenticated receipt contains its txid and selected output commitment/position. Accept a genesis capsule only at the exact initial-commitment position. Derive genesis/profile/deployment from `genesis_document`, never from capsule claims alone.
- [ ] GREEN: run the full module, the preservation gate, and commit `feat(protocol5-wallet): add private note capsule verification`.

### Task 4: Authenticate bounded H+1 state observations

**Files:**
- Create: `src/protocol5_state_reader.py`
- Create: `scripts/read_protocol5_state.py`
- Create: `tests/test_protocol5_state_reader.py`

**Interfaces:**
- Produce `STATE_OBSERVATION_FORMAT = "1soft/protocol5-state-observation/v1"`, `MAX_STATE_OBSERVATION_BYTES = 8_388_608`, `authenticate_observation(raw, engine_genesis, app_genesis) -> tuple[dict, dict]`, and `extends_observation(old, new) -> None`.
- Observation keys are exactly `format`, `state_witness`, and `signed_header`. Authentication derives trust with `trust_from_protocol5_genesis` and calls `verify_protocol5_state_certificate`, which enforces header height = state height + 1.

- [ ] Write failing tests for exact H+1 success; H/H+2/stale/forked heights; wrong validator set/genesis/AppHash; insufficient signatures; changed state; duplicate JSON keys; trailing/overbound response; unsafe endpoint; redirects/proxies/compression; and nonextension of prior commitments, root history, receipts, execution blocks, and spent-nullifier set.
- [ ] RED:
  ```bash
  PYTHONPATH=src:tests:scripts "$P8_PYTHON" -B -m unittest     test_protocol5_state_reader.Protocol5StateReaderTests.test_signed_h_plus_one_authenticates_exact_state
  ```
- [ ] Implement pure verification first. Same-height observations must be byte-identical; newer observations require monotonic height, exact list prefixes, and old-nullifier subset.
- [ ] Implement a key-free reader permitting only `http://127.0.0.1:PORT/`. Make one bounded `/state` ABCI query and one bounded `commit` query at H+1; disable DNS/proxies/redirects; emit one canonical observation. It has no wallet, key, client, prover, or submit operation.
- [ ] GREEN: run the module, preservation, and commit `feat(protocol5-wallet): authenticate H+1 state observations`.

### Task 5: Build the private append-only wallet journal

**Files:**
- Create: `src/protocol5_wallet.py`
- Create: `tests/test_protocol5_wallet.py`

**Interfaces:**
```python
class Protocol5Wallet:
    def __init__(self, path, app_genesis, engine_genesis, controller,
                 *, create=False, clock=time.time_ns): ...
    def sync(self, observation: bytes, *, expected_revision: str) -> dict: ...
    def import_note(self, capsule: bytes, owner_spend_secret: bytes,
                    *, expected_revision: str) -> dict: ...
    def prepare(self, *, note_id: str, recipient_owner_key: str,
                value: int, valid_until: int) -> dict: ...
    def approve(self, review: dict, confirmation: str) -> dict: ...
    def recover(self, decision_id: str) -> bytes: ...
    def export_capsule(self, decision_id: str, output_index: int) -> bytes: ...
    def status(self) -> dict: ...
```
- Use a new SQLite application ID/version 1 with only `config`, `observations`, `notes`, and `decisions`. Bounds: 32 observations, 16 notes, 16 decisions, 8 MiB total observations, 4 KiB capsules, and genesis transaction limits. Derive status by audit; no cached balance/status column is authority.

- [x] Write storage RED tests for exclusive `0600` creation, parent fsync, WAL/FULL, exact schema, no implicit migration/repair, symlink/hardlink/sidecar aliases, reopen audit, no eviction, canonical rows, monotonic clocks, rollback, and corrupt/reordered/deleted rows.
- [x] Write workflow RED tests. Prepare must leave `iterdump()` unchanged and invoke neither client nor prover. Require one unresolved decision per input note, exact fee/change with two positive outputs, current authenticated observation, and valid recipient key/window.
- [x] Write approval/recovery RED tests. Approval rederives review/revision, creates two private openings, calls opcode 4 and prover once, decodes TransactionV1, checks all public identities, and scans it for known secret sequences. Inject process exit after SQLite commit; reopen and recover byte-identical TransactionV1 with zero client/prover calls.
- [x] Write reconciliation RED tests. Exact bytes are `executed_exact`; different bytes with all fourteen identical public fields are `executed_equivalent`; changed public fields are `conflicting_spend`. Winning execution precedes expiry. Missing evidence retains the hold until certified `height + 1 >= valid_until`, then releases it. Exact/equivalent execution admits change atomically and permits only payment output export.
- [x] RED:
  ```bash
  PYTHONPATH=src:tests:scripts "$P8_PYTHON" -B -m unittest     test_protocol5_wallet.Protocol5WalletTests.test_lost_approval_return_recovers_exact_transaction_without_reproving
  ```
- [x] Implement audit-derived storage. Reverify all observations, capsules, reviews, transactions, openings, and lineage on open/status. Never include secret material in `status()`.
- [x] Client/prover work precedes SQLite. Expose no transaction until one `BEGIN IMMEDIATE` stores review, exact transaction, hold, and output openings. Persistence failure returns no bytes; post-commit loss is exact recovery.
- [x] GREEN:
  ```bash
  ONE_P5_CLIENT="$P8_DEV_TARGET/debug/shielded-development-client"   ONE_P5_PROVER="$P8_DEV_TARGET/debug/shielded-development-prover"   PYTHONPATH=src:tests:scripts "$P8_PYTHON" -B -m unittest test_protocol5_wallet
  ```
- [x] Run preservation and commit `feat(protocol5-wallet): add durable private wallet journal`.

### Task 6: Add one-attempt delivery, collection, and reconciliation

**Files:**
- Create: `src/protocol5_transport.py`
- Create: `src/protocol5_delivery.py`
- Create: `tests/test_protocol5_delivery.py`

**Interfaces:**
- `submit_once(endpoint, transaction, request_id) -> dict` permits one loopback `broadcast_tx_sync`, verifies Comet's plain SHA-256 wire hash, and returns only `endpoint_admitted`, `endpoint_declined`, or sanitized `unresolved`.
- `Protocol5Delivery` exposes `prepare`, `send`, `inspect`, `collect`, `import_receipt`, `export_receipt`, and `reconcile`, bound to one wallet ID/genesis/endpoint and a separate SQLite journal.

- [x] Write transport RED tests for one connection, request ID/hash, complete-response framing/length/content type, duplicate headers, non-200, an overall elapsed deadline including drip-feed peers, malformed JSON, DNS/nonloopback/redirect/proxy refusal, and no retry.
- [x] Write delivery RED tests for disjoint wallet/delivery sidecars; mutation-free prepare bound to the wallet and delivery revisions; durable attempt before `_dispatch_guard`; crash after claim; refusal to resend; and no release on CheckTx decline.
- [x] Test separate collection/reconciliation. Collection stores the exact authenticated H+1 observation without wallet mutation. Reconciliation validates the supplied wallet and original transaction before sync, binds the classification to the revision returned by sync, and preserves exact/equivalent/conflict/expiry precedence.
- [x] RED:
  ```bash
  PYTHONPATH=src:tests:scripts "$P8_PYTHON" -B -m unittest     test_protocol5_delivery.Protocol5DeliveryTests.test_attempt_is_durable_before_io_and_never_retried
  ```
- [x] Implement the P4 ordering invariant—claim, release locks, key-free I/O, store observation—using only Protocol 5 transaction/receipt/certificate rules. Do not import P4 monetary authority.
- [x] GREEN: run the focused modules and the direct repository regression. The manifest-checked wrapper remains intentionally unqualified until Task 10 binds the finished Protocol 5 source set. Commit `feat(protocol5-wallet): add one-attempt shielded delivery`.

### Task 7: Expose a secret-safe local CLI

**Files:**
- Create: `scripts/protocol5_wallet.py`
- Create: `tests/test_protocol5_wallet_cli.py`
- Modify: `src/protocol5_controller.py`
- Modify: `src/protocol5_wallet.py`
- Modify: `src/protocol5_delivery.py`

**Interfaces:** Commands are `init`, `owner-key`, `sync`, `import-note`, `prepare`, `approve`, `recover`, `export-capsule`, `status`, `delivery-init`, `delivery-prepare`, `delivery-send`, `delivery-collect`, `delivery-reconcile`, and `delivery-inspect`. Secrets/capsules enter through stdin or `0600` files, never argv/environment. Outputs use exclusive no-follow `0600` creation. `recover` accepts the pre-approval review ID as well as the durable decision ID, so a return lost after commit remains recoverable without either controller executable.

- [x] Write actual-process RED tests for init→owner-key, genesis import, sync, prepare, approval, lost-return recovery, capsule handoff, and delivery. Assert argv/stdout/stderr/process listings never contain known secret hex/base64/decimal sequences. These tests use explicit codec/state fixtures and do not claim Halo2 qualification.
- [x] Add malformed tests for duplicate flags, missing confirmation, wrong revision, unsafe files/modes/symlinks, existing output, trailing stdin, and forbidden raw-secret arguments.
- [x] RED:
  ```bash
  PYTHONPATH=src:tests:scripts "$P8_PYTHON" -B -m unittest     test_protocol5_wallet_cli.Protocol5WalletCliTests.test_terminal_lost_return_recovers_exact_transaction
  ```
- [x] Implement thin dispatch; keep monetary/certificate/capsule/journal/delivery rules in source modules. Emit closed canonical results and sanitized nonzero refusal. Measure and pin the executable inode before launch, bound output while reading, wipe the request on every exit path, and retain controller-free recovery by review ID.
- [x] GREEN: run the module, preservation, and commit `feat(protocol5-wallet): add local continuity CLI`.

### Task 8: Add source-bound real-engine qualification

**Files:**
- Create: `reference/protocol5-wallet-qualification-settings-v1.json`
- Create: `scripts/run_protocol5_wallet_engine.py`
- Create: `tools/release/check_protocol5_wallet.py`
- Create: `tests/test_protocol5_wallet_runner.py`
- Create: `tests/test_protocol5_wallet_gate.py`

**Interfaces:** Inputs are exact CometBFT, worker, client, prover, descriptor, KAT, toolchain, policy, empty genesis template, and expected client/prover hashes. Output and sibling artifacts are fresh external paths. Required check IDs are `four-validator-wallet-init`, `recipient-secret-separation`, `actual-proof-recipient-payment`, `approval-lost-return-recovery`, `one-attempt-no-resend`, `signed-h-plus-one-sync`, `capsule-mutation-matrix`, `recipient-import-and-spend`, `conflicting-nullifier-not-original`, `expiry-hold-preservation`, `wallet-delivery-restart`, `validator-controller-boundary`, and `secret-leakage-scan`.

- [x] Write checker RED tests binding source commit/tree/cleanliness, inputs/binaries, profile/deployment/genesis, processes, exact checks, sanitized wallet/delivery manifests, artifacts, and all false claims. Every omission/mutation/duplicate fails. Missing pins are accepted only as unqualified `unassessed`.
- [x] Write runner RED tests for four validators, controller processes with `node: null`, no controller paths in validator commands/homes, owned cleanup, fresh outputs, sanitized names, and no private absolute paths in public projections.
- [x] RED:
  ```bash
  PYTHONPATH=src:tests:scripts:tools/release "$P8_PYTHON" -B -m unittest     test_protocol5_wallet_runner test_protocol5_wallet_gate
  ```
- [x] Implement: create A/B with distinct synthetic secrets; put only A's genesis commitment in fresh genesis; give A only B's owner key; A pays B plus change with opcode 4; exit after wallet commit/before return; reopen and recover exact bytes without reproving.
- [x] Claim one attempt, submit once, wait for commit and H+1, collect/reconcile A, export output-0 capsule, import it in B, and have B spend with another actual proof.
- [x] Mutate every capsule field; inject a separate same-nullifier randomized conflict; cross expiry without receipt; crash/reopen wallet/delivery at durable boundaries; reject stale/unsigned/wrong-genesis/profile/deployment observations.
- [x] Scan validator homes, node DBs, snapshots, reports, artifacts, logs, process argv/environ, TransactionV1, and public manifests for all known secrets, WitnessV1, and ProverRequestV1. Private journals are excluded; only sanitized size/hash/schema receipts are artifacts.
- [x] GREEN: run runner/checker tests, preservation, and commit `test(protocol5-wallet): add source-bound real-engine qualification`.

### Task 9: Build and execute qualification on a clean implementation commit

**Files:** No tracked changes unless a detecting regression and root-cause repair are required.

- [ ] Full Python gate:
  ```bash
  PYTHONPATH=src:tests:scripts:tools/release "$P8_PYTHON" -B scripts/run_tests.py
  ```
- [ ] Separate Rust suites:
  ```bash
  CARGO_TARGET_DIR="$P8_WORKER_TARGET" cargo +1.97.1 test --locked --offline     --no-default-features --features worker     --manifest-path tools/shielded-consensus/halo2/Cargo.toml -- --test-threads=1
  CARGO_TARGET_DIR="$P8_DEV_TARGET" cargo +1.97.1 test --locked --offline     --no-default-features --features dev-prover     --manifest-path tools/shielded-consensus/halo2/Cargo.toml -- --test-threads=1
  ```
- [ ] Separate release builds:
  ```bash
  CARGO_TARGET_DIR="$P8_WORKER_TARGET" cargo +1.97.1 build --release --locked --offline     --no-default-features --features worker     --manifest-path tools/shielded-consensus/halo2/Cargo.toml     --bin shielded-verifier-worker --bin shielded-sandbox-probe
  CARGO_TARGET_DIR="$P8_DEV_TARGET" cargo +1.97.1 build --release --locked --offline     --no-default-features --features dev-prover     --manifest-path tools/shielded-consensus/halo2/Cargo.toml     --bin shielded-development-client --bin shielded-development-prover     --bin shielded-profile-builder
  ```
- [ ] Run preservation. Require tracked profile/KAT/schema/toolchain/policy, `crypto-v1.json`, circuit/Cargo/P1-4 trees to match `$PHASE8_BASE`. Smoke the optimized worker with zero argv/profile startup. Record binary hash drift without rewriting historical P5 manifest evidence.
- [ ] Commit implementation fixes and require a clean tree. Reports name this exact commit/tree. For a real failure, retain private evidence, add the smallest detecting test, fix the cause in a new commit, rerun narrow then affected source-bound gates.
- [ ] Re-run existing P5 consensus and state-sync real-engine runners with the new client/prover and unchanged worker/profile, and validate both through `check_protocol5.py`. They are regression evidence, not replacements for historical receipts.
- [ ] Run wallet qualification:
  ```bash
  mkdir -p -m 700 "$P8_EVIDENCE" "$P8_PRIVATE"
  PYTHONPATH=src:tests:scripts:tools/release "$P8_PYTHON" -B     scripts/run_protocol5_wallet_engine.py     --engine "$COMETBFT"     --worker "$P8_WORKER_TARGET/release/shielded-verifier-worker"     --client "$P8_DEV_TARGET/release/shielded-development-client"     --prover "$P8_DEV_TARGET/release/shielded-development-prover"     --profile tools/shielded-consensus/profile/profile-descriptor-v1.bin     --kat tools/shielded-consensus/profile/kat-v1.bin     --toolchain tools/shielded-consensus/profile/toolchain-manifest-v1.json     --policy tools/shielded-consensus/profile/sandbox-policy-v1.json     --genesis "$P8_PRIVATE/protocol5-template.json"     --expected-client-sha256 "$P8_CLIENT_SHA256"     --expected-prover-sha256 "$P8_PROVER_SHA256"     --output "$P8_EVIDENCE/wallet-01.json"
  PYTHONPATH=src:tests:scripts:tools/release "$P8_PYTHON" -B     tools/release/check_protocol5_wallet.py "$P8_EVIDENCE/wallet-01.json"
  ```
- [ ] Continue only if checker reports qualified; otherwise stop at exact `unassessed`. Never register failed/incomplete/dirty/skipped/overclaiming evidence.

### Task 10: Register evidence and integrate

**Files:**
- Create: `tools/protocol5-wallet/README.md`, `COMPONENT_MANIFEST.json`, `DEPENDENCY_RECEIPT.json`
- Create: `docs/PROTOCOL5_WALLET_CONTINUITY.md`
- Modify: `tools/shielded-consensus/README.md`, `docs/PROTOCOL5_SHIELDED_CONSENSUS.md`, `docs/ABCI_INTEGRATION.md`, `docs/ROADMAP.md`, `README.md`, `SOURCE_MANIFEST.json`

- [ ] Generate the component manifest from exact files/evidence. Record clean implementation commit/tree; release binary/engine hashes and bytes; unchanged profile/KAT/deployment; settings; report/checker/artifact identities; check roster; finite limits; and all false claims. Keep only basenames/hashes/byte counts, never private paths/logs/secrets/journals/capsules.
- [ ] Generate the dependency receipt from separate locked offline worker/dev-prover metadata graphs and their deterministic union. Record no new Python direct dependency. State that inventory is neither security review nor legal clearance.
- [ ] Document exact behavior and limits: imported private capsule, known-commitment scan, one trusted-host journal, synthetic keys, H+1 authentication, one attempt. Explicitly deny encrypted discovery, production custody, hostile-host/cross-device safety, public deployment, real funds/users, anonymity, metadata privacy, independent review, and economic value.
- [ ] Preserve historical P5 evidence. Describe opcodes 3/4/5 as later controller-only additions; do not change circuit/profile/deployment identities or claim old receipts executed Phase 8.
- [ ] Rebuild `SOURCE_MANIFEST.json` deterministically with every Phase 8 source/test/script/setting/vector/plan/doc/manifest. Exclude itself, private runs, binaries/targets, SQLite sidecars, capsules, secrets, raw reports, and logs.
- [ ] Validate JSON with duplicate-key/closed-key checks; recompute all hashes/bytes; check Markdown links; scan for absolute private paths, secret vectors, placeholder markers, and unsupported claims. Re-run the wallet checker on external evidence.
- [ ] Final regression: full Python; separate worker/dev suites; zero-argv worker smoke; preservation; `git diff --check`. Rerun real engines only if registration changes executable/source-bound inputs or prior evidence is unresolved.
- [ ] Commit `docs(protocol5-wallet): register finite continuity evidence`; require a clean tree.
- [ ] Review every commit against `$PHASE8_BASE`. If main advanced, integrate through the authorized owner without force push and rerun checks affected by conflicts.
- [ ] Cherry-pick or merge reviewed commits locally, verify final commit/tree/status and manifest identity. The existing session authorization covers a review PR and merge for this branch. Public CI/deployment, DNS, external-user tests, and paid compute remain excluded.

## Completion Condition

Phase 8 is complete only when a clean, source-bound, strict-checker-qualified real-engine run shows two distinct private wallet journals using actual Halo2 proofs on four local validators; A pays B using only B's public owner key; A recovers byte-identical TransactionV1 after a lost approval return without reproving; delivery records one attempt before I/O and never retries; H+1 authentication alone reconciles execution; B verifies/imports one exact private capsule and spends that note; hostile mutation/restart/leakage gates pass; P1-5 protected surfaces remain unchanged; and all production/public/security/economic claims remain false.

Registration checkpoint: real consensus, state-sync and wallet receipts are strictly qualified. Final manifest-checked regression, review and GitHub integration are recorded in the external delivery receipt.
