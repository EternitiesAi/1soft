# P8 validator milestone contract

Base: a03606b421086bc5dfff5f16949235579afe3822. Branch:
development/p8-validator-20261006. Root owns implementation; peers review only.

Deliver a separately versioned P8 application, genesis, verifier bridge and AS-OF
full-state authentication. Preserve all P1–P7 runtime and the first P8 native
circuit/profile/worker/kernel bytes. The native library is reused without prover
features in the consensus bridge. No old note migration or owner-allowance
composition is inferred.

The proof network is derived from an acyclic bootstrap core binding version,
chain, immutable four-validator roster, profile, verifier binary, asset, mission,
fee and a fresh pool identity. Network-dependent notes and known-answer proof
are excluded from that core; the exact complete externally supplied genesis
is separately committed by the P8 AppHash and authenticated next signed header.
Never describe the bootstrap digest as a hash of the complete genesis.

Admission and proposal attempts are nonreserving. Ordered proposal/finalization
share one deterministic transition. Same-input nullifiers remain stable across
intents. Finalize stages; SQLite commit updates checkpoint and block evidence
atomically. Restart replays retained blocks and checks exact responses/hashes.
Unavailable verifier is a hard failure, not a transaction success/refusal cache.

Qualification requires the actual pinned CometBFT0.38.25 binary, four fresh local
validators, native received-note spending, valid competing-spend refusal,
ordered dependency/race checks, exact same-store restart, four-state agreement,
and signed H+1 full-state replay. Pin source/tree, engine/bridge/KAT identities;
record and reap owned processes; preserve raw sanitized successes/failures.
Mock/unit results remain separate from actual engine evidence. State sync and
recipient custody are subsequent gates unless actually implemented and tested.

No Actions, paid/public compute, public deployment/DNS/site, other projects or
messages, real funds/production keys, force pushes or specialist-audit claims.
Private PR and expected-head merge remain authorized after the finite gates pass.
