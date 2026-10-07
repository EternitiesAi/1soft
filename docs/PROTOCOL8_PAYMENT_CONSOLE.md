# Local P8 payment console

The Linux/WSL terminal console makes the protected wallet and one-attempt payment
caller usable by a local operator. The wallet remains the authority for encrypted
custody, original intent, retained wire and signed state; the payment caller
remains the authority for the transport journal. The console adds no consensus
profile, custody key generation, public endpoint or automatic recovery send.

## Inspect, review and submit

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
file, hash-checked and removed. Those values appear on the local terminal: do not
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
qualify cryptography. The fresh actual console gate remains pending qualification.

The actual gate retains all 22 wallet and 13 payment checks on four real CometBFT
validators, and adds 10 console checks. It exercises 19 actual console invocations,
six console refusal paths alongside the unchanged six legacy payment refusals,
private display comparison before redaction, cancellation with unchanged wallet
bytes/no journal/no RPC, one confirmed submission, a deliberately lost real node
reply, signed unresolved/exact/conflict states and child reaping. Private human
stdout is hashed and discarded; only sanitized lines are retained. Native replay
and altered-receipt checks remain separate evidence.

Scope is finite synthetic funds on one trusted Linux/WSL host. Actual process-kill
at a journal marker, power loss, hostile-host custody, rollback resistance, latest
freshness, production privacy/key management, independent operators/signers,
scale, economics, specialist review and public launch remain separate gates.
