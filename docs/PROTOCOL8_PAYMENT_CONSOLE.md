# Local P8 payment console

The Linux/WSL terminal console makes the protected wallet and one-attempt payment
caller usable by a local operator. The wallet remains the authority for encrypted
custody, original intent, retained wire and signed state; the payment caller
remains the authority for the transport journal. The console adds no consensus
profile, custody key generation, public endpoint or automatic recovery send.

## Inspect, review and submit

The additive [receive-to-delivery journey](PROTOCOL8_WALLET_JOURNEY.md) exposes
explicit observation, import, independently confirmed preparation, export and
private delivery. Its changed console source has its own
[fresh actual journey receipt](../evidence/protocol8-wallet-journey/20261007/journey-03.json);
the historical receipt below remains scoped to its captured runtime.

Use an initialized protected wallet, an external private credential file and the
full trusted genesis SHA. A new payment journal belongs in a separate existing
owner-only directory. The engine/application are separately started and owned.

```sh
python -B scripts/protocol8_console.py \
  --workspace /home/operator/wallet-config --genesis-sha256 TRUSTED_FULL_SHA \
  --credentials /home/operator/private/credentials.json inventory

python -B scripts/protocol8_console.py \
  --workspace /home/operator/wallet-config --genesis-sha256 TRUSTED_FULL_SHA \
  --credentials /home/operator/private/credentials.json submit \
  --endpoint http://127.0.0.1:26657 --journal /home/operator/private/payment-1 \
  --txid EXACT_RETAINED_TXID
```

`doctor` checks configuration without authenticating the encrypted wallet.
`inventory` authenticates it and shows note commitments and obligation state;
it does not invent an available balance. `review` uses the same payment arguments
and displays the protected original recipient, amount, expiry, fee and validity.
The private projection is written by the wallet CLI into a temporary owner-only
file, hash-checked and removed. Its v2 projection includes a stable private blind
derived through domain-separated HMAC from the wallet AES key and public identity
context. The blind is omitted from displays and public receipts; its presence
prevents the retained file SHA from testing guesses about low-entropy intent.
Repeated reviews remain byte-identical for unchanged intent and authenticated state.
Those values appear on the local terminal: do not
record or share its output when it contains private intent.

`submit` requires the complete typed `SUBMIT <txid> <wire_sha256>` confirmation.
Enter or any different input cancels before a payment child starts. After exact
confirmation, the console obtains a second authenticated projection and requires
its complete content and digest to match, then checks the journal is still absent.
Only the existing payment caller can persist the attempt and send the retained
wire. An existing journal, attempted or completed obligation refuses submission.
A new journal cannot bypass the wallet attempt marker.

`status` and `reconcile --packet /home/operator/private/signed-state.json` use the
same original payment arguments. Status authenticates local records; reconcile
verifies signed state without sending a transaction. The console keeps prepared,
incomplete marker, unknown outcome, admission, unresolved hold, exact execution
and conflicting-spend hold distinct. Admission is not execution. Signed AS-OF
execution is not a current-network freshness claim. Retry stays disabled.

An optional global `--receipt /home/operator/private/console-receipt.json` writes
a new owner-only canonical public metadata receipt. It contains state, process
identities, pins, hashes and protected child replies, but no private recipient,
amount or payment expiry. It is not created by default. It cannot reconstruct the
private intent later; a receipt-write failure never authorizes resubmission.

## Runtime pins and qualification

The additive wallet `review --txid ... --output ...` command authenticates and
rebuilds the retained original request, then writes a protected private projection.
Its normal CLI stdout reports only public identity, size and digest. Existing
commands and protocol bytes retain their meaning. These wallet source changes
change the runtime hash: old configurations must refuse changed code. No automatic
configuration migration, repinning or repair is included. Preserve original wallet,
credentials and evidence before any separately authorized upgrade.

Focused tests cover exact confirmation, cancellation, changed review refusal,
journal/path/endpoint protection, distinct states, receipt collisions and actual
disposable child identity/reaping. Fake authority tests are labeled and do not
qualify cryptography. The [fresh actual console receipt](../evidence/protocol8-payment-console/20261006/console-05.json)
passed all 12 console, 13 inherited payment and 22 inherited wallet checks at
clean runtime `b5dfabb36504b4fb29e8bf6fa0ca5daf4ef63e11`. All 19 console invocations and their
protected children were reaped without forced cleanup. Six console refusals and
all inherited refusal lanes passed; cancellation left wallet bytes unchanged,
created no journal and made no request. One exact confirmed submission reached
the real node; the reply was lost, and signed exact execution recovered without
resending. All 54 altered console and 30 altered payment receipts refused after
recomputed linkage and stream hashes. Separate native replay verified four proofs
and three static-quorum signed AS-OF states. Twenty-three console methods and 36
wallet/payment/envelope/process methods passed without skips. Private rendered
intent was checked against the actual request before being redacted and discarded.
The v2 private file hash covers a domain-separated keyed blind that never enters
public receipts; the gate independently reconstructs its exact digest from fixture
custody. Raw human stdout receives a discarded random 256-bit blind before hashing.
Intermediate03 passed at its earlier source; final05 alone qualifies the hardened
runtime. Failed04 omitted a required refusal-review position in its assertion;
that negative report remains separate. Final05 requires the literal 19 child-command
map and all six private reviews, including both fresh-journal refusal paths.
These commitments do not certify production privacy.
The public checker cannot reconstruct that private intent or independently
recompute excluded-key journal MACs; native certificate replay is separate.

The actual gate retains all 22 wallet and 13 payment checks on four real CometBFT
validators, and adds 12 console checks. It exercises 19 actual console invocations,
six console refusal paths alongside the unchanged six legacy payment refusals,
private display comparison before redaction, cancellation with unchanged wallet
bytes/no journal/no RPC, one confirmed submission, a deliberately lost real node
reply, signed unresolved/exact/conflict states and child reaping. Private human
stdout is committed with a domain-separated SHA256 and fresh random 256-bit blind,
then both raw stdout and blind are discarded; only sanitized lines are retained.
This opaque commitment cannot be recomputed from public artifacts. The fixture
independently reconstructs the keyed private projection from its controlled
synthetic custody before checking the retained file digest. Native replay
and altered-receipt checks remain separate evidence.

Scope is finite synthetic funds on one trusted Linux/WSL host. Actual process-kill
at a journal marker, power loss, hostile-host custody, rollback resistance, latest
freshness, production privacy/key management, independent operators/signers,
scale, economics, specialist review and public launch remain separate gates.
