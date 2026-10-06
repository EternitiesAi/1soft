# P8 recipient consensus

This separately versioned development application connects the frozen P8 native
recipient-transfer relation to CometBFT 0.38.25. It adds full-state authentication
and durable ordered execution. P1–P7 and the original P8 relation/profile/kernel
remain unchanged. Existing P7 grants and notes do not migrate into this pool.

The public statement has 13 fields and an exact 3,560-byte wire, including a
3,136-byte Halo2 proof. Typed recipient notes hide their opening inside the proof.
The stable input nullifier is independent of a fresh payment intent, so creating
another intent cannot authorize spending the same input twice. Public network,
asset, mission, validity window, fee and output commitments remain observable.
This is a finite synthetic development qualification, not production privacy.

## Authentication and lifecycle

An acyclic bootstrap binds the chain, immutable four-validator roster, native
profile, verifier executable digest, asset, mission, fee and fresh pool identity.
Network-dependent initial notes and KAT are excluded from this core. The complete
genesis is an external trust pin and is separately committed into every P8
AppHash. Genesis authorization is still supplied by the caller.

Admission does not reserve an input or intent. Prepare, Process and Finalize
execute the same ordered transition. A received output may be spent later in
the same proposed block; reversing that dependency is refused. A proposal with
two valid conflicting spends is refused, and Prepare retains only the valid
first spend. Finalize stages state; Commit writes the checkpoint and retained
block response atomically. Restart replays all blocks and audits exact responses,
request identities, genesis and AppHash. P8-specific tables reject earlier schemas.

The verifier-only executable is built with `--no-default-features`, independently
of the synthetic fixture/prover build. The host hashes an opened executable inode
and executes that same descriptor. Cache hits remeasure the executable. Child
processes use an empty environment and bounded CPU, memory, descriptors, output
and wall time. No seccomp or hostile-host isolation is claimed. Unavailable
verification quarantines the private endpoint without committing or caching a
transaction refusal. Recovery is an ordinary same-store application restart.

`protocol8_certificate.verify_state` replays the full native history, recomputes
AppHash, and verifies the signed header at state height H + 1 under the externally
pinned static roster. This proves AS-OF state, without freshness. It does not
authenticate a different genesis supplied by an attacker.

## Bounded qualification

The local gate generates five genuine proofs for a fresh roster/bootstrap:
receive, re-spend, competing input spend, duplicate intent and a conserving
wrong-fee spend. It starts four actual validators on loopback, checks dependency
order and nonreserving admission at each application, commits receive/re-spend,
refuses valid competing/duplicate-intent payments, restarts one node with the
same stores, compares four states and verifies a signed next header. A separate
actual-proof database probe injects a commit failure and verifies atomic recovery.
Raw public proofs, sanitized logs, executable identities, PID/start-time/exit
receipts and full-state witness are retained. Synthetic openings, private validator
keys and SQLite stores are excluded from delivery.

Run `scripts/run_protocol8_engine.py --help` for the explicit executable/KAT/output
inputs. Use a fresh output path and clean committed source. Validate the result
with `tools/release/check_protocol8_engine.py REPORT --worker VERIFIER` for a
separate native replay and certificate check. Lifecycle unit tests deliberately
use a labeled fake worker and are reported separately from this actual gate.

Development limits are 64 heights, 32 retained transaction attempts, two wires
per block, 16 notes and a 512 KiB full state. Reaching them requires a new protocol
design; the application does not silently evict replay authority or notes.

P8 recipient custody/import/recovery, certified wallet dispatch, state sync,
independent operators, external cryptographic review and public deployment remain
separate gates. Snapshot requests explicitly decline. No real funds, production
keys, paid compute, public infrastructure or GitHub Actions are used by this gate.
