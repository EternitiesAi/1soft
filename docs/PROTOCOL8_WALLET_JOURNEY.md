# Local P8 receive-to-delivery console

The Linux/WSL console now exposes signed observation, explicit private note import,
native preparation, exact wire export and private opening delivery. The protected
wallet owns note validation, encryption, locks, original proof/intent holds and
certified output authority. The console owns presentation and a separate preparation
confirmation. Submission remains the existing independently confirmed one-attempt
payment path; no command combines preparation with a send.

Use an initialized wallet, externally supplied owner-only credentials, separately
trusted genesis SHA and pinned native binaries as described in
[wallet commands](PROTOCOL8_WALLET_CLI.md). These commands create no credentials,
select no remote trust, start no node and query no public endpoint. Inputs and
outputs below are explicit absolute paths in existing owner-only directories.
Replace capitalized identifiers with the exact trusted local values; they are
placeholders, not a published network or funded accounts.

```sh
python -B scripts/protocol8_console.py --workspace /home/operator/wallet-config \
  --genesis-sha256 TRUSTED_FULL_SHA --credentials /home/operator/private/credentials.json \
  observe --packet /home/operator/private/signed-state.json

python -B scripts/protocol8_console.py --workspace /home/operator/wallet-config \
  --genesis-sha256 TRUSTED_FULL_SHA --credentials /home/operator/private/credentials.json \
  import-note --opening /home/operator/private/received-opening.json \
  --wire /home/operator/private/received-wire.tx --output-index 10

python -B scripts/protocol8_console.py --workspace /home/operator/wallet-config \
  --genesis-sha256 TRUSTED_FULL_SHA --credentials /home/operator/private/credentials.json \
  prepare --commitment EXACT_IMPORTED_COMMITMENT --request NEW_REQUEST_ID \
  --destination RECIPIENT_PUBLIC_KEY --payment 4 --valid-until 32 --payment-expiry 56

python -B scripts/protocol8_console.py --workspace /home/operator/wallet-config \
  --genesis-sha256 TRUSTED_FULL_SHA --credentials /home/operator/private/credentials.json \
  export --txid EXACT_RETAINED_TXID --output /home/operator/private/original-wire.tx
```

Observation authenticates a signed AS-OF state and does not establish current
network freshness. Import requires the actual certified origin wire, selected
output and recipient-controlled opening. `--genesis-note` is a separate explicit
source form; it cannot be combined with `--wire`. Duplicate authenticated import
is idempotent. Invalid origin/value/expiry/secret/blind, wrong recipient, wrong
output, forged state and rollback refuse without changing the wallet.

Preparation displays the requested recipient, amount and expiry locally, then
requires exactly `PREPARE <input_commitment>`. Enter or a different line cancels
before a wallet child starts. A confirmed preparation invokes the existing native
prover and durable hold path. It creates no transport journal, marks no attempt,
sends no request and grants no submission capability. Held or attempted input
cannot be reused. No balance, funding, amount or recipient is guessed. Request IDs
and openings are not displayed; credential/opening contents remain files.

Use [payment review and submission](PROTOCOL8_PAYMENT_CONSOLE.md) as a separate
command with its exact txid/wire SHA confirmation and second authenticated review.
Unknown outcomes remain held and cannot be retried. After signed exact execution
is reconciled, selected private delivery is explicit:

```sh
python -B scripts/protocol8_console.py --workspace /home/operator/wallet-config \
  --genesis-sha256 TRUSTED_FULL_SHA --credentials /home/operator/private/credentials.json \
  deliver --txid EXACT_EXECUTED_TXID --output-index 10 \
  --output /home/operator/private/recipient-opening.json
```

Delivery writes a new owner-only opening file and sends it to nobody. The exact
exported wire is separate. The recipient must obtain both through an independently
authorized private channel, authenticate their own signed observation, and import
the exact output with their own recipient credentials. A filename or output hash
cannot confer recipient authority. Existing files, symlinks and unsafe ancestry
refuse; neither export nor delivery overwrites a file.

An optional separate `--receipt` stores bounded canonical public metadata and
protected child replies. It contains no opening/credential/request contents or
private recipient/amount/expiry. A receipt cannot alias the private output. Failure
of that preflight creates neither file; failure after an actual effect never
authorizes another attempt. Private values shown on the terminal are local
disclosure. The gate compares them to owned fixture input before redaction and
uses discarded random blinds for stdout commitments. It does not certify hostile
host or production privacy.

The wallet core, wallet CLI and native formats are unchanged from PR83. Their
configuration/runtime pins remain byte-compatible with that base; console source
has a new identity. Configurations older than PR83's wallet-review change still
refuse that changed wallet runtime. No migration or automatic repinning occurs.

The fresh actual journey gate is pending qualification. It preserves the existing
12 console, 13 payment and 22 wallet checks, routes lifecycle commands through real
console/wallet children, observes live preproof holds, and separately prepares and
natively verifies a recipient re-spend. That extra wire is not submitted or
chain-executed. Source-bound qualification, semantic receipt tamper checks and
separate native replay remain necessary; earlier receipts qualify only their own
source. Finite synthetic funds on one trusted host only. Production custody,
freshness, independent operators/signers, marker-kill/power loss, rollback/scale,
economics/listings, specialist certification and public launch remain separate.
