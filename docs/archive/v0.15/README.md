# 1soft — native cryptocurrency development

**v0.15: validated execution snapshots.** The node now forks read-only validated
committed state for transaction checks and proposals, avoiding repeated historical
receipt-signature validation on each request. Startup validation and current
transaction rules remain intact; only a durable block commit promotes staged state.

This complete source package is development software, not a public mainnet, audited
wallet, backed-dollar issuer, bank account or card program. No real funds. The
separate Resident/Luna/Psyche lanes and the deployed public website are unchanged.

## Read first

- [Execution architecture](docs/VALIDATED_EXECUTION.md)
- [Observed verification](docs/VERIFICATION.md)
- [Continuation context](docs/HANDOFF.md)
- [Actual validator acceptance](docs/RUN_REAL_VALIDATORS.md)

The complete local suite passed 797 cases across 16 completed groups (37 new cases
included); all 89 required sources matched. The real consensus engine gate remains
unassessed with zero executed engine steps. See the raw evidence, failure records,
scope and limitations rather than treating a test count as mainnet readiness.

## Local commands — no GitHub Actions

```sh
python scripts/verify_checkout.py
PYTHONPATH=src:tests python -m unittest test_execution_snapshot -v
python scripts/measure_execution_trials.py --output NEW_DIRECTORY
python scripts/local_dev.py network
```

Use installed pinned dependencies. Downloads are never implicit in the network
command. The execution measurement is local CheckTx work, not network TPS or gas.

This archive follows the complete local development history. It is not an exact
clone of GitHub main, which has a separate state-wallet lineage and partial node
imports. No history is force-replaced. Source-publication restrictions and actual
publication results are stated in RELEASE.json. Monetary policies, public supply,
issuer/reserve arrangements and production deployment remain open or unbuilt.

Third-party code retains its original notices. No new open-source license is
selected. Private signing keys, secrets and live participant data are not included.
