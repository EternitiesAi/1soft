# v0.13 verification — compact authenticated state

September 24, 2026 (America/Chicago). Local, disposable development. No Actions,
DNS changes, paid compute, public endpoints or real funds.

## Executed results

| Gate | Observed result | Scope |
|---|---|---|
| Parent v0.12 ZIP | SHA-256 matched; 531 manifest entries passed | Starting artifact, preserved local lineage. |
| Complete local Python suite | 705 passed; zero skips, failures or errors | 16 completed batches, exact unique case-ID reconciliation. |
| New cases, included above | 82 passed | 38 tree/oracle cases, 44 application/client/runner cases. |
| Separate JS budget reference | 30 passed | Still not integrated cross-rail accounting. |
| Second JS state-proof implementation | 6 roots, 39 proofs agreed; 39 changed roots rejected | Bottom-up implementation versus compressed Python tree. |
| Deliberately weakened controls | All 5 produced assertion failures | Root, height, signed-root, shared allowance, atomic capacity. |
| Full required-source inventory | 79/79 matched | Complete local package, not remote completeness. |
| Actual-engine gates | Unassessed; zero engine steps/checks | Engine absent and normal module-host DNS fails. |

`evidence/v013/test-coverage.json` lists all 705 exact case IDs and reconciles them
once. The new 82 tests are not added again. Batch 13's first attempt was interrupted
by the container command deadline while sharing a command with completed batch 12.
Its incomplete log is preserved. Batch 13 was rerun alone and passed; only the
completed run is counted. No single-process full-suite pass is claimed.

Tests exercise inclusion and noninclusion, table/key binding, exact query sets,
modified records/roots/paths, proof-set mixing, genesis isolation, legacy vectors,
proposal-versus-commit visibility, actual process crashes before/after commit,
aggregate agent limits, revoked authority, stale-snapshot races, execution receipt
proofs, and an actual read-only command-line invocation. A separate uncompressed
recursive Python oracle checks root construction, plus randomized small maps.

The actual native-execution measurement ran 1,024 signed transfers in 16 local
application blocks. A one-account witness decreased from 1,212,982 to 3,961 bytes
including the same signed-header overhead. Both verify under the same synthetic
committee root. The node still uses whole-state storage and rebuilds the tree;
these bytes are not a throughput, gas, live-network or anonymous-payment claim.
See `evidence/v013/witness-size/result.json` for exact numbers.

## Compatibility and resource checks

An explicitly opted-in fresh protocol-3 genesis with `state_commitment: smt-v1`
is required. The default commitments for protocols 1/2/3 are unchanged; vectors
were generated using the parent v0.12 implementation and replayed exactly. No
in-place migration was attempted. Unknown modes cannot silently fall back.

An atomic row-capacity guard rejects a state-growing transaction before native
commit. The tests verify the failed payment leaves balances, counter and receipt
unchanged, and that empty application blocks can still advance. This is a bounded
prototype, not a sustainable production storage/economic policy.

## What did not run or change

The full engine runner now contains an additional opt-in SMT scenario. It retains
all legacy protocol and quorum checks and requires actual compact account/receipt
queries against real RPC when an engine runs. This authored integration did not
execute. The local network gate and direct compact engine attempt both record
unassessed with no fake fallback. The normal Go-module HEAD request failed DNS;
no alternate tunnel, mirrored download or proxy bypass was used.

The compact client is read-only. It does not replace the existing signer's
freshness/checkpoint journal, unlock a vault, submit a transaction, or update the
payment-dispatch journal. The old full-witness verifier remains compatible with
the new root for explicitly configured local chains. Static committee fixtures do
not establish live consensus or independent operators.

No source upload was retried for the previously blocked native-core integration,
ABCI transport or payment-job source. A PR status comment records the completed
local checkpoint only. Remote main and PR #2 remain separate from this local
archive's history; no force push or merge is performed. Final observed refs and
local commit are recorded in RELEASE.json after packaging.

The production storage engine, general light client, dynamic validator changes,
independent security audit, protected customer custody, coin launch, reserves,
public token economics, bank/card integration and multi-asset settlement remain
unimplemented or unassessed. Brand and domain deployment are unchanged.

The companion release-check JSON records fresh-extraction checks and new-subset
reruns after packaging. Those are repeated tests, not additional unique cases.
