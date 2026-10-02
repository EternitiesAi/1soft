# 1soft — native money and persistent-agent accounts

Independent native Layer 1 development for people and persistent agents.
**Development only. No launched cryptocurrency, backed dollars, bank/card service,
production custody or completed independent security audit.**

## v0.13: compact authenticated records

An explicit fresh-genesis `state_commitment: smt-v1` option for protocol 3 lets a
client verify selected account, permission, budget and receipt records rather than
receiving the whole ledger. Default protocol-1/2/3 commitments remain unchanged.

A local application test executed 1,024 signed transfers. One-account evidence
shrank from 1,212,982 to 3,961 serialized bytes, including the same signed-header
overhead. The signatures were synthetic committee fixtures, not live consensus.
Node storage is still whole-snapshot; this is client-evidence progress, not a
production node-scaling or anonymous-payment claim.

Read [compact state](docs/COMPACT_STATE.md), [verification](docs/VERIFICATION.md)
and [handoff](docs/HANDOFF.md). The compact verifier and transfer preflight are
read-only. They do not yet replace the existing signing wallet/collector.

## Local execution, no Actions

With pinned dependencies installed:

```sh
python scripts/verify_checkout.py
PYTHONPATH=src:tests python -m unittest discover -s tests -p test_state_tree.py -v
PYTHONPATH=src:tests python -m unittest discover -s tests -p test_compact_state.py -v
python scripts/verify_compact.py --help
```

The two new modules contain 82 tests. The full local source ran 705 unique Python
cases across completed batches. All full-suite IDs and evidence are preserved.
The separate JS budget reference still has 30 tests; it is not cross-rail native
accounting. A second JS Merkle implementation provides a separate algorithm check.

```sh
python scripts/check_compact_reference.py --output evidence/my-reference-run
python scripts/measure_compact_witness.py --output evidence/my-measurement
python scripts/local_dev.py network --engine /absolute/path/to/cometbft
```

Output directories must be new. No implicit downloads, hosted minutes, paid
resources or public network. The real-engine gate remains **unassessed** because
the pinned CometBFT executable is unavailable here. Its compact-v3 RPC acceptance
checks are authored but unexecuted.

This complete archive follows the previous local development history. Remote main
has a separate wallet lineage and a partial node import. No prior blocked source
upload was rerouted and no main/PR merge was performed. GitHub status comments
record local results; they are not source publication. See RELEASE.json for exact
heads. Public branding, monetary policy, issuance, reserves, bank/cards and real
multi-asset integration remain open or unbuilt.
