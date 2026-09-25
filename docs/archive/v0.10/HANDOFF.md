# Continuation — 1soft v0.10

No GitHub Actions. No cloud spending or DNS changes. Dom is arranging 1soft.org separately; do not race that lane. Main's state wallet and the full local archive use different v0.8 histories. Preserve main and the existing PR #2 feature branch rather than force-replacing either history.

Read RECEIPT_COLLECTION.md and VERIFICATION.md. New source is receipt_collector.py; payment_transport.py now offers refresh_receipt and export_receipt, and the dispatch CLI offers refresh/export-proof. The new gate is scripts/check_receipt_collection.py (NOT named test_receipt_collection.py, to avoid discovery collision). The independent receipt subset has 13 files, while the full local inventory has 61.

Local tests: all 535 passed across 16 explicit groups, including 37 new receipt cases; 30 separate JS cases passed. Four weakened variants were caught by assertion failures. Existing wallet/ledger/payment cases were rerun. No real CometBFT process ran. New tests use actual loopback HTTP and public, synthetic committee fixtures only.

The collector makes read-only fixed-method RPC requests. It captures one state, derives the exact payment's height as an untrusted hint, gets block/commit evidence, and waits only within explicit bounds for h+1. The parent re-verifies everything before recording receipt_verified. Missing evidence leaves the original payment pending/unresolved; refresh cannot send, replay, sign, or free a counter. Existing proof can be exported for independent checks without network calls. The static verifier and whole-state snapshots remain development limitations.

The complete archive's real-engine runner was extended to require actual RPC receipt collection once an engine is available; it remains unexecuted. The remote feature patch does not include that previously unpublished runner or the blocked ABCI transport. Full GitHub import remains partial. Record actual remote and local commits separately in RELEASE.json and never present either as the other's history.

Next: obtain a supported local real-engine run; execute upstream codec checks and both validator protocols. Then connect verified account/receipt data to the account UI and replace full snapshots with bounded authenticated state proofs. Do not increase unit counts or polish site claims in place of real consensus evidence. No real funds, public issuance, custody keys, card/bank integration or mainnet deployment until their own readiness gates pass.

Publication completed on PR #2 at remote commit 29705061c3cbb8b09ac18001c2b980d3183215a1. Nine changed/new paths match their tested local Git blob identities. Main was not moved. The local source commit is separately recorded in RELEASE.json.
