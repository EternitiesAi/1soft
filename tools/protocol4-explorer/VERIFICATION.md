# Verification boundaries

The verifier checks new source and externally pinned dependency bytes before and
after the exact discovered Python cases. No skips or expected failures count as a
pass. The tests execute native P4 fixture replay, actual private SQLite/read-only
HTTP boundaries, exact capsule verification and CLI processes; the fixture quorum
signatures are synthetic and do not qualify a real engine.

```sh
python tools/protocol4-explorer/tools/verify.py --report /private/explorer-tests.json
```

The separate `scripts/run_protocol4_explorer_receipts_engine.py` first invokes the
unchanged real P4 delivery harness with a pinned CometBFT engine, including the
full validator turnover. It then exercises explorer, capsule export, verification
and archive reopen from original evidence after disposable wallet state is gone.
A clean committed source and unchanged pinned binary are required. Result JSON
lists exactly which engine/product assertions passed; fixtures cannot replace it.

Rendered browser checks are reported separately with synthetic attribution,
checkpoint hierarchy, navigation/search, constraint/receipt details, explicit
full-history download, focus behavior and narrow-width rendering. Local policy
expiry clears the display using a chunked timer; it never collects or renews.
A 16 MiB display-response cap and 20-row pages bound the response and rendering;
these are logical limits, not a production performance or memory qualification.

The UI is not a wallet, collector, compact verifier, public deployment, independent
host proof, globally coordinated journal, external settlement or security review.
