# Authorized validator registry — isolated development profile

This component implements threshold authorization, delayed scheduling, cancellation,
epoch transitions, deterministic validator-update records, persistence and snapshot
replay. It is an **isolated registry experiment**, not an activated P4 coin or a
replacement wallet. Existing `src/` monetary, ABCI, state-sync, wallet, archive and
explorer modules are unchanged and do not import it.

Base: local transition foundation `7d860457fa85950f81aaa67f7cd3c98a979d5bbc`, tree
`24b7a034b26616ee9a6e824da3b7b5e7910e72fb`, above PR #23 at
`289a78056b86ebdd5878d285027f5c78562e0767`. Parallel PR #24 is not merged; its
different proposal numbering requires reconciliation before combining the lines.

## Authority

A uniquely versioned genesis pins 3–16 separate administrative public keys and an
integer n-of-m threshold of at least two. The example uses **2 of 3 administrative
keys**. This is not consensus >2/3 voting, staking or a selection of public governance.
Administrative and consensus keys cannot overlap, including in a proposed roster.
All administrative signatures, including those beyond the threshold, must verify.

Commands bind the chain, exact registry genesis, authority epoch, administrative
nonce, expected validator epoch/hash, validity heights and exact schedule/cancellation.
The signing preimage has a dedicated domain. Approvals are sorted and unique;
unknown signers, duplicate approvals, noncanonical bytes and altered bodies refuse.
There is no signing, key-loading or broadcasting function outside test fixtures.

This is centralized administrative control for development, not protection against
a compromised threshold. Authority rotation is explicitly unsupported: its epoch
must be zero. Rotation/recovery and eventual public governance remain undecided.

## Authorization, emission and activation

One schedule may be pending. Its selected emission E must be at least the pinned
delay after acceptance (minimum two blocks), within the pinned future window. A
roster needs at least four keys and obeys a pinned per-key power limit no greater
than 3333 basis points. These are key-level limits, NOT independent-operator proof.

The deterministic transition produces the update delta only at **E**, describes
next-set announcement at **E+1**, and switches its active epoch/set at **E+2**.
An integrating CometBFT engine would provide changed last-commit information at
E+3; this component does not claim to observe that input or manage proposer priority.
Zero power is used only for removal entries, not in complete rosters.

Cancellation requires another threshold-signed command naming the exact proposal,
strictly before E. It consumes a nonce and appends a receipt; the original receipt
is never edited. Cancellation at/after emission refuses. Another schedule cannot
be accepted on the same height a previous set activates. Invalid commands produce
code 1 without consuming nonce or changing authority; due activation still proceeds.

## Persistence and restoration

`finalize_block` computes without changing SQLite. `commit` compares the exact
committed base and atomically saves state, hash and last block/result in one WAL
transaction. Identical retries converge; stale writers or conflicting blocks refuse.
The last result is re-executed on read, not trusted merely because it was rehashed.
Reopening does not re-emit an already committed update or replay authorization.

Reads reconstruct all registry state from immutable signed receipts. Fresh snapshot
import requires the exact external expected hash and an untouched, explicitly
created registry. Pending/emitted/active state is replayed, not trusted from metadata.
Bootstrap creates a marker, not invented local block results. The marker is checked
against authorized history after continuation. The import does not authenticate the
external source of the supplied root and is **not CometBFT state sync**.

The separate SQLite file uses private POSIX storage and a unique application ID.
Existing wallet, dispatcher, empty or unknown databases are refused, not migrated.
Aliased files/sidecars refuse. Trusted local OS/filesystem is assumed: no hostile-
host custody, backup guarantee, hardware power-loss proof or whole-workspace rollback
resistance is claimed.

## Bounds and commands

Eight commands per block, 64 KiB per command, 256 KiB total command bytes per block,
256 accepted historical commands, and 16 MiB state are development limits. Capacity
refuses new governance rather than evicting receipts; already due activation and
empty blocks remain possible. Complete replay is a correctness reference, not a
throughput/scalability result. Its AppHash commits registry state, not coin balances.
The serializer emits only FinalizeBlock field-three probe bytes, NOT a complete
production ABCI response.

From the complete checkout with existing pinned dependencies:

```sh
python tools/validator-registry/tools/verify.py
python tools/validator-registry/scripts/demo.py --output /private/new-registry-demo
python tools/release/check_release.py --output /private/new-full-results
```

The demo uses public deterministic fixture keys in memory, reopens after every
block, cancels one proposal and advances snapshot-restored copies alongside the
source. It writes no private-key files and launches no node. CLI `registry.py`
supports init, inspect, unsigned draft, local block execution, export and fresh
restore. No command contacts a network. A failed output after commit is not rollback;
inspect retained state before retrying. Never use fixture keys/genesis for funds.

## Next integration boundary

A separately versioned composite native state must commit money AND registry in
one atomic boundary and derive/check current/next rosters through full ABCI. It
needs mempool/proposal semantics, administrative fee/rate policy, production signer
handling, full response encoding, dynamic snapshot/receipt/wallet adapters and
changing-validator engine tests. These results cannot be inherited from PR #23's
static-validator runs. Public governance/economics remains undecided.

Reference: CometBFT v0.38.25 `spec/abci/abci++_methods.md`, FinalizeBlock, Git blob
`ca4614069cff735c24b20c3d015be874ed21cc4c`. No public deployment, Actions, paid compute,
DNS/site changes, Resident/Luna work, production keys, real funds, merge or force-push.
