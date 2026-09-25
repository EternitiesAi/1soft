# Read-only native receipt collection — v0.10

The payment dispatcher can now collect its own receipt evidence from the configured local development node. A person or agent no longer needs to construct a certificate file manually. This does not launch the chain or give an agent signing authority.

## Command and behavior

Use the existing `scripts/payment_dispatch.py` common options: a separately pinned genesis and digest, the private dispatch journal, literal-loopback endpoint, and explicit trust expiry. After queueing a signed transfer, run its new `refresh --txid NATIVE_TXID` subcommand. The default performs one bounded collection pass. `--read-attempts 3` explicitly permits up to three attempts to obtain the captured state's next-height commitment; it does not retry a payment.

The complete command shape is:

```sh
python scripts/payment_dispatch.py --genesis genesis.json --genesis-sha256 PINNED_DIGEST --journal PRIVATE_DIR/dispatch.sqlite --endpoint http://127.0.0.1:26657/ --trust-expires-utc EXPLICIT_UTC_DEADLINE refresh --txid NATIVE_TXID --read-attempts 3
```

Replace the uppercase placeholders with the independently selected development values. There is no default trusted network or automatic genesis discovery. Command success means the refresh operation completed; inspect `collection_status` and `receipt_verified`, not the exit code alone, to determine whether evidence was verified.

`refresh` sends only a fixed `/state` ABCI query and fixed-height `block`/`commit` reads. It cannot broadcast, replay, unlock a key, change a recipient, or clear a payment's authority counter. A timeout, missing receipt, or RPC error leaves the previous payment status intact. An absent receipt in an untrusted response is not proof of nonpayment.

The collector uses the receipt row only as a lookup hint. It obtains the transaction block and its signed commit, plus the signed header at snapshot height **h+1** that commits the state produced at **h**. If that next block is not available, the bounded optional read attempts keep the same snapshot instead of chasing each new chain head. A normal pass takes four RPC reads; the maximum configured pass takes seven. There is no background polling.

## Trust and verification boundary

The HTTP worker collects **untrusted** evidence and cannot mark a payment verified. The parent process calls the existing certificate verifier and dispatch journal proof path again. This checks the pinned, static validator set, signatures, state hash, transaction inclusion, native receipt, and exact signed transaction bytes. A successful worker label is insufficient. Trust expiry is checked before reads and again before accepting a newly collected proof.

The new `export-proof --txid NATIVE_TXID --output receipt.json` subcommand exports the existing, reverified proof without contacting the endpoint. It refuses to overwrite an existing file. This is suitable for a separate verifier or later audit. Historical proof export is not a claim of latest balance, current authority, or unexpired present trust. The existing `export` command still exports only the original signed transaction.

## Bounded local transport

Only an explicitly supplied `http://127.0.0.1:PORT/` endpoint is accepted. The worker does not resolve hostnames, use environment proxies, follow redirects, or accept compressed responses. Request methods and paths are fixed. Response framing, JSON-RPC IDs, duplicate JSON keys, byte limits and canonical encodings are checked. The full-state witness is limited to 4 MiB; individual RPC responses are capped at 8 MiB; collected packets remain under the existing 16 MiB verifier limit. A child-process deadline bounds the complete read operation at 15 seconds. These are development bounds, not scalability or production endpoint-security claims.

The private local journal remains the continuity store. A crash after reading evidence but before accepting it leaves the original payment unresolved. An already accepted proof survives restart and can be read/exported without another network request. Separate journals, old complete-workspace restores, a hostile OS, and other devices remain outside local coordination.

## Executed evidence versus pending integration

37 new cases passed, including actual loopback HTTP reads, delayed commitments, missing/tampered evidence, different network data, exact-byte hints, untrusted worker results, trust expiry during collection, process interruption, recovery and independent proof export. One scenario submits a real native-ledger transfer through a fixture endpoint, loses the response, then recovers its receipt entirely through read-only RPC calls. The committee signatures are synthetic fixture signatures: no real CometBFT process generated them.

The full local archive's actual-engine runner now requires the collector to verify a real RPC receipt when the engine is available. That added engine path has not run. The remote PR retains the independently runnable subset; it does not upload the previously blocked ABCI transport or replace the partial full-node import.

Run `python scripts/check_receipt_collection.py`, or both explicit parts `--parts 2 --part 0` and `--parts 2 --part 1`, with installed pinned dependencies. `RECEIPT_MANIFEST.json` checks the 13 required files. This does not shorten or supersede the full-node source inventory.

## Source basis

The inspected CometBFT v0.38.25 `rpc/core/blocks.go` supplies the Commit/Block RPC behavior. Commit responses may be labelled non-canonical at the current height while still carrying a signed header; this client verifies signatures instead of treating that label as evidence of invalidity. The application-state/next-block relationship is documented in CometBFT's application requirements. The collector is original integration code, not a new consensus implementation.

```text
https://github.com/cometbft/cometbft/blob/v0.38.25/rpc/core/blocks.go
Git blob: c7dc2e8e5ee92b08348a677eeb65ff9dc084cfdb
https://docs.cosmos.network/cometbft/v0.38/spec/abci/Requirements-for-the-Application
```

No Actions, Cloudflare changes, paid compute, public endpoints, production keys, real funds, issuer backing, card issuance or independent security audit is part of this checkpoint.
