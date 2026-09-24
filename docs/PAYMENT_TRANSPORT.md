# Native payment transport — v0.9

This is an additive, loopback-only development transport for an **already signed native transfer**. It accepts the canonical envelope exported by the offline wallet, the local certificate-backed wallet, or the newer repository state-wallet. It never accesses a key, invents a signature, converts an asset, creates a card payment, or runs consensus.

## Implemented boundary

`queue -> dispatching -> endpoint observation -> independently verified receipt`

Queueing verifies the envelope's cryptographic signature, chain/genesis, canonical bytes and native-transfer shape. It does **not** reestablish the signer's latest account authority or balance. The account/agent nonce identifies a local slot: another payment cannot silently replace that slot. The original bytes remain exportable.

The dispatch confirmation binds the exact bytes, signer, endpoint, pinned genesis and explicit trust deadline. It is an approval binding, not a password or proof of human identity. A holder of the signed envelope can submit it elsewhere; this interface cannot revoke that capability.

Before any network request, the SQLite journal durably records an attempt. A separate POSIX lock prevents another process from using the same journal during dispatch. The HTTP worker receives only public signed bytes. It performs one `broadcast_tx_sync` JSON-RPC request to an explicitly configured `http://127.0.0.1:PORT/` endpoint, with a process-enforced total deadline. DNS hostnames, non-loopback destinations, credentials, redirects, proxy configuration, implicit retries and compressed responses are not supported. This is a local-development restriction, not a production endpoint-security design.

CometBFT's synchronous broadcast returns CheckTx, **not final transaction execution**. The application therefore records `endpoint_admitted`, `endpoint_declined` or `unresolved`; none means settled, refunded or safe to replace. A timeout after actual local-ledger execution is exercised by the tests. The same source transaction remains reserved in the dispatch journal even when an endpoint claims rejection.

An interruption after dispatch was recorded leaves `dispatching`. No automatic resend occurs after restart. An explicitly approved `replay` uses **exactly the same signed bytes**, not a new amount, fee, recipient, nonce or signature. It does not promise exactly-once network delivery: correctness still requires the native ledger's replay/nonce rules. Separate journals, other devices, old backups and direct submission are outside this local coordination.

## Receipt handling

`prove` invokes the existing static-validator certificate verifier with the requested native transaction ID. It verifies block inclusion and the receipt recorded in the quorum-committed application state. The exact envelope bytes must also match: native intention IDs hash the body, while the network transaction hash includes the signature. A certificate for a differently signed envelope cannot satisfy this request merely because its body hash matches.

Verified proof bytes and their digest are persisted. Reading a verified status rechecks the stored proof, including signatures; flipping a database status flag cannot manufacture that result. A receipt prevents further dispatch through this journal. No absence proof, cancellation, automatic balance release or bank/card reconciliation is introduced.

Trust comes from an independently selected genesis digest and explicit deadline, not an RPC-supplied validator list. This remains a fixed-validator development verifier, not a general light client. Historical execution evidence is not a latest-balance query. Live-network provenance and independent validator operation cannot be inferred from signatures alone. All delivered certificates are labelled synthetic fixtures.

## Commands

With the pinned dependencies installed, test the published subset without Actions:

```sh
python scripts/test_transport.py
```

For bounded runs, execute all three parts (`--parts 3 --part 0`, then `1`, then `2`). Each report states its exact test IDs and scope; one part alone is not the complete subset. `TRANSPORT_MANIFEST.json` verifies ten required files and does not weaken or replace the full-node manifest.

The dispatch CLI requires a separately pinned genesis, a private journal directory, a literal local endpoint and an explicit UTC trust deadline. Run `python scripts/payment_dispatch.py --help` for the common flags. Commands are `queue`, `send`, `replay`, `status`, `events`, `prove`, and `export`. `send` and `replay` require the exact dispatch confirmation shown by `queue/status`. Signed envelopes exported with one terminal newline are accepted; their canonical transaction bytes do not change. No existing export file is overwritten.

Use a **new** dispatch database, never a signing-journal database. There is no implicit migration or write-back to either wallet's database. Run the real-engine gates before using this against a genuine development node.

## Evidence and limitations

56 new tests exercise actual loopback sockets, RPC framing, process deadlines, proxy/redirect rejection, canonical bytes, explicit replay, process crashes before I/O and after a response, conflicting local payments, forged evidence and proof recovery. A local HTTP fixture can execute the real native ledger before dropping its reply; its subsequent certificate is signed by synthetic fixture validators, not a consensus engine.

The complete local archive is based on local v0.8 `c94d5c1`, whose wallet differs from remote main `941c624`. The addition consumes their shared exported transaction format and does not overwrite the remote wallet/outbox. Shared monetary and verifier source hashes were compared before publication. Test counts for these two different full source trees are not added together.

No GitHub Actions, paid compute, public service, real funds, production keys, launched network, USD backing, or external settlement is part of this checkpoint. Journal integrity assumes a private trusted local filesystem; it is not protection against a malicious operating system or restoration of an older complete workspace. Full-state certificates and bounded local journals are not production scalability claims.

Primary RPC reference inspected: CometBFT v0.38.25 `rpc/core/mempool.go`, Git blob `93442dfe7651db778439dd0318294f43c7e670ce`. Its `BroadcastTxSync` returns CheckTx and explicitly does not wait for execution. No upstream consensus implementation is copied into the transport.
