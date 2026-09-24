# v0.9 transport publication and verification

September 24, 2026. Additive branch based on remote main 941c6241d89761f2074c121af29539c354f6cdcd. The existing wallet_state.py, state_wallet.py, root documentation, original placeholder, source inventory and archived Actions are preserved.

## Source distinction

The complete downloadable development archive extends local v0.8 c94d5c1 (442 cases), not the different remote v0.8 wallet implementation. In that full local tree, all 498 discovered Python cases passed with zero skips/failures/errors across 16 bounded processes; 56 are new transport cases. The separate JavaScript reference passed 30 cases. No completed single-process full-suite run or full remote-main test run is claimed. The exact local logs, successful case IDs and incomplete runs are in the archive.

The new component has an independently runnable ten-file TRANSPORT_MANIFEST.json. Its six new source/test files and four common dependencies were checked against the published Git blob identities. Native core and verifier bytes match both local and remote bases. The complete-node manifest has not been shortened to hide the incomplete remote node import. Do not add the two different v0.8 trees' test counts together.

## Observed transport tests

All 56 new transport cases passed locally, including actual loopback HTTP requests, command-line queue/send/prove/export, process crashes before I/O and after an HTTP reply, one-workspace process exclusion, explicit exact-byte replay, malformed/oversized/truncated RPC responses, deadlines, proxy/redirect rejection and specific-payment receipt verification.

One HTTP fixture executes the actual native ledger and then drops the response. The client remains unresolved despite that execution, until it verifies a synthetic signed receipt for the exact payment. The fixture is not CometBFT and its validators do not run consensus. The tested behavior must not be advertised as a live chain or distributed settlement result.

The first implementation failed to recheck stored proof when reading verified status. The initial regression log is preserved. The corrected implementation checks the certificate hash, cryptographic signatures and exact envelope on every verified-status read. Tests also reject a valid signature over the same body from a different key even when a deliberately dishonest synthetic committee attests it; the network wire bytes must match the queued envelope.

## Not achieved

The normal Go module host failed DNS resolution in the local runtime. The real-network runner verified the 58-file full local source inventory, then returned unassessed with zero engine steps because CometBFT is absent. No mock engine replaced this gate. No Actions, paid compute, production key, real funds, public service or bank/card operation was used.

No wallet database is migrated or coupled atomically to the dispatch database. Queue/signature validation does not prove latest authority or reserve a network balance. A timeout or endpoint rejection does not free a nonce for another payment. Historical proof does not prove latest state or real-world provenance. Fixed-validator trust and a private trusted local filesystem remain assumptions. This is developer verification, not an independent security audit.

Run the subset with installed pinned dependencies:

```sh
python scripts/test_transport.py --parts 3 --part 0
python scripts/test_transport.py --parts 3 --part 1
python scripts/test_transport.py --parts 3 --part 2
```

All three successful reports are required to claim the entire 56-case subset. See PAYMENT_TRANSPORT.md for operation boundaries. Actual upstream codec and validator execution remain the next network acceptance gate.
