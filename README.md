# 1soft — Eternities native finance

An independent native-coin research project for people and persistent agents.
The repository name is a development home, not finalized coin branding.

**Development only. Not a public blockchain, bank, dollar issuer, card program,
secure production wallet, or audited financial system. Do not use real funds.**

## September 24, 2026 checkpoint

The owner designated `xnuonux/1soft` for this project. The private repository and
its original placeholder are preserved. Publication is **partial**, not a full
migration of the delivered v0.6 development archive.

Published code includes the native ledger, 35 inherited native-ledger tests,
33 new checkout/test-runner tests, and an explicit required-source inventory.
The full local archive passes 320 Python tests and 30 separate JavaScript tests.
Those are local development results, not hosted-CI or validator-network results.

Two separate blockers remain:

1. The platform blocked publication of the existing `src/abci_wire.py` twice.
   The rest of the coordinated application import was stopped; the full archive
   remains available in the project conversation. No alternative encoded upload
   or weakened import manifest was used.
2. GitHub Actions reported `startup_failure` with no jobs even for an echo-only
   workflow. The exposed result does not establish the cause. Neither the engine
   build nor native consensus tests executed on GitHub.

See [import status](docs/IMPORT_STATUS.md), [verification](docs/VERIFICATION.md),
and [engineering handoff](docs/HANDOFF.md).

## Native rules already implemented in the full development package

Signed transfers, explicit fees, fixed development-supply conservation, bounded
recipient-constrained agent grants, owner-scoped grant names, revocation and
versioned authority. Protocol 2 also supplies two-sided account opening and key
rotation that preserves account identity/history while invalidating old grants.
The published native ledger contains these rules; the new checkout tests do not
constitute additional cryptocurrency features.

The full package additionally contains block staging, atomic commits, an ABCI
adapter targeting CometBFT 0.38.25, synthetic receipt-verifier exercises, and real
network acceptance runners. A real communicating validator network is still
**unassessed**. Existing synthetic certificates are never live-network evidence.

## Run the published native-core subset

Use disposable test keys only. With a compatible Python environment:

```sh
python -m pip install -r requirements.txt
PYTHONPATH=src python -m unittest discover -s tests -p test_native.py -v
```

This command runs 35 native-core tests. It deliberately does not claim the full
320-test suite, a secure wallet, or distributed consensus.

## Verify the complete development checkout

```sh
python scripts/verify_checkout.py
python scripts/run_tests.py
```

These commands must fail on the current incomplete GitHub import. The inventory
names all 43 required source files and was not reduced to manufacture success.
In the full archive it matches all 43 files and discovers 320 Python tests.
A checksum inventory is not a signature, independent audit, or trust anchor.

Branding, public issuance, supply/allocation policy, licenses, reserve backing,
validator admission and banking/card integrations remain decisions or unbuilt
work. Existing research and interface previews are in the full conversation
archive; they are not live services. Preserve upstream attribution and read
`NOTICE.md` before reuse.
