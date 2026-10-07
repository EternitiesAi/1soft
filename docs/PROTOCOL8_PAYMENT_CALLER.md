# Local P8 payment caller

The Linux/WSL caller submits an already prepared wallet transaction to one
explicit literal loopback CometBFT RPC endpoint. The protected wallet retains
the original wire, durable attempt marker, held input and signed execution
authority. The separate caller journal contains authenticated public transport
metadata. It never generates a replacement transaction or resumes a submission.

## Run an explicit local payment

Use an initialized [protected wallet](PROTOCOL8_WALLET_CLI.md), its complete
trusted genesis SHA and external private credential file. The engine/application
are separately owned and started through the existing operator boundary. Create
the journal in an existing private `0700` directory, separate from the wallet
configuration's closed membership and encrypted-wallet file.

```sh
python -B scripts/protocol8_payment.py \
  --workspace /home/operator/wallet-config --genesis-sha256 TRUSTED_FULL_SHA \
  --credentials /home/operator/private/credentials.json \
  --endpoint http://127.0.0.1:26657 --journal /home/operator/private/payment-1 \
  --txid EXACT_RETAINED_TXID submit
```

Only canonical `http://127.0.0.1:PORT` is supported: no DNS, public/LAN host,
proxy, redirects, URL path, credentials or automatic retry. Loopback is an
explicit local routing choice, not authentication of the node process. It does
not grant the caller access to the private ABCI control socket.

Before opening a connection, submit validates all wallet/native/runtime/genesis
pins and the exact retained wire, fsyncs a new journal and its directory, persists
the wallet's single attempt marker, and fsyncs the journal's `attempt-marked`
phase. It then performs one bounded HTTP `broadcast_tx_sync` request. The
dedicated Linux CLI applies a 20-second total deadline, including headers/body;
it does not replace an existing main-thread alarm from an embedding caller. The
[pinned upstream response schema](https://github.com/cometbft/cometbft/blob/v0.38.25/rpc/core/types/responses.go)
reports CheckTx admission. Its hash is SHA256 of wire bytes, distinct from the
domain-separated P8 txid. HTTP success, node admission or that hash never proves
execution. Malformed, wrong-hash, redirected, oversized, timed-out or lost replies
remain unknown; an explicit admission refusal still retains the original hold.
Raw endpoint diagnostic/data fields are suppressed.

The journal binds absolute journal/workspace path, wallet/config identity,
genesis/runtime SHA, endpoint, txid and exact wire size/SHA with domain-separated
HMAC-SHA256 derived from the external wallet AES key. It includes no credential,
opening, private request or wallet ciphertext. File/directory modes, ownership,
single links, ancestry and atomic replacement remain protected. The existing
wallet configuration lock spans the command and network wait.

## Recovery, status and uncertainty

Repeat the same arguments with `status` to authenticate the journal and actual
wallet. Status does not contact the endpoint or resolve execution:

| Journal/wallet observation | Reported submission state |
| --- | --- |
| Prepared journal, wallet attempt0 | `prepared-not-attempted` |
| Prepared journal, wallet attempt1 | `attempt-record-incomplete` |
| Attempt-marked or unknown journal, wallet attempt1 | `attempted-outcome-unknown` |
| Valid matching node acknowledgment, wallet attempt1 | `admission-accepted` or `admission-refused` |

An existing journal is never a resume-send capability. Choosing a fresh journal
cannot bypass wallet attempt1. A missing, changed or unauthenticated journal
refuses while preserving the wallet obligation. There is no automatic repair,
release, refund, abandon or resubmission operation.

Use `reconcile --packet /home/operator/private/signed-state.json` to authenticate
an explicit closed `{witness, signed_header}` packet through the existing wallet,
then reconcile its exact original transaction. Without `--packet`, only retained
authenticated observations are used. Results are `executed-exact`,
`unresolved-held` or `conflict-held`. Private delivery remains a separate wallet
command after exact certified execution. Reconciliation makes no RPC call and
never retries a submission.

Journal and wallet commits are separate. If interruption occurs before the wallet
marker, the prepared record is reported distinctly. If the marker committed but
its caller journal update did not, status derives incomplete submission from the
wallet's actual attempt counter. Both paths refuse automatic continuation. This
conservative policy may retain a hold for a transaction never sent; it does not
pretend that uncertain remote execution can be rolled back locally.

## Qualification and limits

Focused tests label the fake wallet and exercise actual disposable loopback HTTP
responses, MAC/wire/path/endpoint binding, strict reply handling, no-resend and
injected failures on either side of the marker. Those tests do not qualify crypto,
consensus or actual power-loss durability.

The new actual gate reuses the unchanged 22-check four-validator wallet journey,
with actual wallet and payment CLI processes. An owned test proxy forwards one
exact transaction to the real node and discards the real admission reply. Recovery
must retain the one attempt and authenticate signed exact execution without another
request. A second genuine competing spend must produce a signed conflict hold.
The fixture also constructs a prepared journal, records an actual encrypted-wallet
marker through the wallet CLI and observes the resulting incomplete state without
submission. It does not kill a process at that marker or claim such a crash test.
The fresh actual gate requires clean-source qualification before being described
as passed. Closed receipt checks establish consistency; separate native replay
verifies public proofs/certificates.

The fixture's separate initial funding and genuine competitor transactions use
the existing node routing; only the prepared wallet payment uses the new caller.
Their routes and receipts are recorded separately. Public journal envelopes and
their hashes bind status/reconciliation evidence; external private credentials
are excluded, so the closed checker does not independently authenticate their MAC.

Scope is finite synthetic funds on one trusted host. A private-host HMAC is not
rollback resistance or hostile same-user isolation. Latest-network freshness,
production credential management/privacy, independent hosts/signers, trust-period
policy, power loss, scale, economics, specialist review and public launch remain
separate gates. No public service, production funds or new consensus/crypto profile
is introduced.
