# v0.11 update: persistent payment jobs

See [payment jobs](docs/PAYMENT_JOBS.md) and [verification](docs/PAYMENT_JOBS_VERIFICATION.md). New stable local task IDs prevent accidental re-preparation of a purchase under a later nonce through this jobs interface. The native protocol is unchanged; real validator execution remains unassessed. This full local archive is not a clone of remote main. No Actions or DNS changes.

---

# 1soft — native coin and persistent-agent finance

**v0.10 local development package. Not a launched Layer 1, bank, issued card,
USD-backed issuer, or production wallet. No real funds.**

This checkpoint adds read-only native payment receipt collection. The client can
retrieve evidence for a queued payment, verify the exact receipt, and export its
proof without manually constructing certificate files. Refresh never signs,
sends, replays, or releases a payment's counter. Missing evidence stays unresolved.

Actual local HTTP, process interruption and native-ledger execution are tested.
The committee certificates remain synthetic. No real CometBFT engine has run here;
the network gate reports unassessed, with no simulated-consensus fallback.

## Read first

- [Receipt collection and proof export](docs/RECEIPT_COLLECTION.md)
- [Payment transport](docs/PAYMENT_TRANSPORT.md)
- [Verification record](docs/VERIFICATION.md)
- [Continuation handoff](docs/HANDOFF.md)

No GitHub Actions, DNS/Cloudflare changes, paid compute, public services or real
funds were used. Domain setup for 1soft.org remains the owner's separate lane.

## Installed-environment tests

```sh
python scripts/verify_checkout.py
python scripts/check_receipt_collection.py --parts 2 --part 0
python scripts/check_receipt_collection.py --parts 2 --part 1
```

The full local inventory checks 61 required files. Both receipt parts cover 37
cases. The full local 535-case Python suite passed across 16 bounded processes,
with exact test-ID reconciliation and no skips. The new 37 are included in 535.
The separate JavaScript reference passed 30 cases and is not a shared native/card
budget. Four deliberately weakened controls were detected by assertion failures.

The receipt subset has a 13-file independent inventory. It does not shorten the
still-incomplete full-node inventory on GitHub. Actual engine integration in this
archive additionally requires client-side receipt collection from real RPC, but
that path has not run without the engine.

## Distinct histories

The complete archive extends local v0.9 f6160b0 and its earlier certificate-backed
wallet. Remote main 941c624 has a different state-wallet implementation. This
checkpoint was published additively to PR #2 at 2970506; main was not overwritten.
The download is not an exact clone of that remote branch. The common monetary and
verifier sources match, and no wallet database is migrated by this feature.

Exact local/remote commits are in RELEASE.json and evidence/v010/publication.json.
The historical blocked ABCI file was not uploaded through an alternative route.
Public branding, economics, reserves, card/cash conversion, independent audit and
production security remain open or unimplemented. Read NOTICE.md before reuse.
