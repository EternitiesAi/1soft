# Atomic private treasury payment lab

A new local component with one actual Halo2 proof linking conserved note value,
the requested merchant output, restricted change and exact parent/grant debits.
This is not a new deployed chain or a Protocol5 migration. P1-P5 and the prior
authority lab remain unchanged.

The hidden payment and recipient are shared cells across all relations. The same
agent secret authorizes the enrolled grant and restricted input, and change stays
in the same mission/parent/grant/epoch/agent scope with the input expiry. Every
accepted transaction has one input, two positive outputs and a fixed public fee.
Input = payment + change + fee in bounded64-bit integers. Merchant note expiry is
independent of agent-grant expiry after purchase; execution must still occur
strictly before transaction until <= grant expiry. No late-spend escape exists.

The exact25-field statement and3200-byte proof have a4008-byte versioned envelope.
The final domain425 commitment binds the entire statement. All note and authority
domains/profile/key fingerprints are separate from earlier components.

## Reproduce the actual gates

Use the configured Rust1.97.1 and Python dependencies. Cargo.lock is pinned; the
gate is offline and never runs Actions, paid compute or a public network. It
requires the corresponding cached packages and builds the real verifier. Missing
packages/prover/engine are not replaced by successful fixtures.

```sh
python tools/private-treasury-payment-lab/scripts/qualify.py \
  --cargo /absolute/path/to/cargo \
  --target-dir /absolute/external/build-target \
  --output /absolute/existing/external/evidence/treasury.json
python tools/private-treasury-payment-lab/scripts/qualify.py \
  --check /absolute/external/evidence/treasury.json
cd tools/private-treasury-payment-lab/scripts
python -m unittest test_qualify -v
```

The runner requires clean committed source and fresh report/log/fixture paths. It
runs ten Rust tests, generates six actual fixture proofs and runs thirteen actual
ledger/recovery tests with its just-built pinned binary. One additional real
proof is generated in the Rust gate. It retains sanitized command output and
source/log/binary identities. The offline parser test uses synthetic log strings
only to attack parsing; these strings never establish executed behavior.

For direct ledger tests use `TREASURY_BINARY` and `TREASURY_FIXTURES` from the
runner's external build target and generated `.fixtures` directory. Tests never
silently skip when those inputs are missing. Proof fixtures contain only public
statements/proofs and public synthetic genesis, and are generated deterministically.

## Durable local execution

`Ledger.apply(raw,height)` selects exact current authority, admits a known
historical note root separately, verifies the real proof and commits the parent,
selected grant, value/authority nullifiers, two outputs, fee tally, monotonic
height and exact raw receipt in one serialized FULL-sync SQLite WAL transaction.
It rejects replays and repeated request identities even under different proofs.
The depth-four tree admits at most seven payments after the two-note genesis.

`Outbox.retain(raw)` atomically keeps exact bytes and holds the input and current
parent/grant fragments. `claim(txid)` durably authorizes one external attempt
before returning those bytes. Claimed means the attempt may not have started;
it never means sent or paid. A crash before I/O or before commit leaves an unknown
obligation indefinitely. Missing receipts, failure, expiry, conflict or revocation
provide no permission to retry, re-sign, re-prove or discard it. Export retrieves
the exact original. `record_local_receipt` requires identical executed bytes in
this trusted local ledger; it is not validator-authenticated reconciliation.

Retention is not proof generation, current-state review or payer approval. This
outbox is not the P5 wallet. It has no API to release a missing obligation, and
therefore favors safety over availability until the future certified resolution
contract exists. Separate/copied/rolled-back journals are outside its guarantees.

## Trust and unsupported claims

Trusted local POSIX host, owner-only files and coordinator; caller-selected
synthetic genesis, deterministic synthetic randomness and agent secrets; two
fixed grant slots. Enrollment/revocation are trusted operator operations without
owner signatures. No validator consensus/certificates, merchant redemption,
encrypted note discovery, cross-device fencing, hostile-host protection,
relationship/metadata privacy, production custody/privacy/security, real-funds
safety or economic value is established. AI review is not independent specialist
cryptographic review. The bridge is bounded but is not the P5 seccomp worker.

Next promotion gate: fresh-genesis validator execution of this exact combined
relation and current authority, followed by certified wallet obligations and
merchant disclosure/redemption. None may inherit this local receipt as proof of
consensus. See the [design](../../docs/superpowers/specs/2026-10-04-atomic-private-treasury-design.md).
