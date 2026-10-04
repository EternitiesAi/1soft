# Protocol 4 consensus and state-sync boundaries

This document records the security boundary qualified by
`tests/test_protocol4_hostile_boundaries.py`.

## Engine-provided last-commit metadata

`Protocol4Application.finalize_block()` receives `decided_last_commit` from
CometBFT through the ABCI adapter. The application checks the exact active
roster, address-to-power mapping, vote flags, duplicate identity, and the
strictly greater-than-two-thirds voting-power threshold. It does **not** verify
Ed25519 signatures or reconstruct a signed consensus header in this callback.
That is deliberate: the application callback is not the independent light
client.

The metadata therefore cannot be presented as an independently authenticated
certificate. `src/commit_verifier.py` owns that separate claim: it verifies the
header hash, chain, validator commitments, proposer, every signature slot, and
quorum against a separately pinned trust anchor. The hostile-boundary test
proves that a forged header is rejected even when application-shaped vote
metadata is accepted at its intended engine boundary.

## State-sync integrity

Protocol 4 state sync binds the offer to the expected genesis digest and the
engine-provided AppHash. The complete canonical payload is hashed, replayed from
genesis, audited, and installed atomically. Malformed, reordered, truncated,
duplicated, forged-state, and wrong-AppHash inputs must leave the recipient at
its prior height with no committed or snapshot-marker rows.

The application validates `sender` as a bounded string but does not assign peer
identity or quarantine a peer. It returns no application-level sender rejects.
Peer selection, peer scoring, and transport-level quarantine remain the
CometBFT responsibility. This test suite does not invent an application peer
identity system; it qualifies content integrity and the no-mutation guarantee
only.

## Limits

These are local adversarial API tests, not an independent multi-operator
consensus qualification, cryptographic audit, public RPC review, or mainnet
readiness claim. Public deployment must preserve loopback-only development
defaults until a separately reviewed network and transport boundary exists.
