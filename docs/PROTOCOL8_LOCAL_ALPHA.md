# Local recipient wallet alpha

This new P8 interface is separate from the historical P4 browser product. Its
local controller invokes the existing protected console as a child for every
operator action. It constructs no proof/transaction, reads no wallet plaintext,
calls no node directly and cannot replace protected custody or signed authority.

The interface has overview, signed receive/import, separately confirmed payment
preparation, private original review, one send, status/reconciliation and explicit
new local output files. Only authenticated opaque note/transaction identifiers
are listed; no balance, spendability or fresh-network authority is inferred.
Preparation and send require the original console's exact confirmation tokens.

The browser displays private recipient/amount/expiry values locally for review.
Those values travel between this trusted local browser and loopback controller;
they are not retained in public receipts/logs or browser storage. This is a local
operator display, not hostile-browser/host confidentiality. No CDN or third-party
assets/telemetry are loaded. Display values are inserted as text, never HTML.

Each server has a fresh in-memory session token, exact `127.0.0.1` origin/Host checks,
same-origin request checks, no CORS, no-store headers, frame refusal and a strict
content policy. Duplicate action IDs are claimed before child execution, and
concurrent actions refuse. A lost HTTP reply never retries an action. The durable
wallet and journal remain authoritative across server restart; session memory is
not custody. File ancestry/no-overwrite/pins are checked by the protected callers.

The new native startup batches the existing valid/corrupt KAT and actual profile
identity checks inside one ephemeral verifier process. Its bounded input/output,
environment, resource limits, pins, wall deadline and reaping remain. Legacy mode
is explicit component measurement only, never fallback. Parameter/circuit/wire/
network/monetary rules are unchanged. Runtime and worker binary pins change:
existing wallets refuse this successor. Do not repin or migrate existing custody.
Initialize only fresh disposable development wallets for this alpha.

The native decoder validates the public header, fields and exact wire length;
it leaves proof parsing to the verifier. The fixed last-byte corruption changes
only proof bytes, so a valid decodable KAT remains decodable. Malformed incoming
KAT syntax refuses the entire startup. A corrupt KAT cannot satisfy both logical
checks; there is no fallback to legacy startup.

Example for a freshly initialized development wallet and explicit local endpoint:

```sh
python -B tools/p8-wallet/scripts/serve_wallet.py \
  --workspace /home/operator/private/fresh-config \
  --credentials /home/operator/private/credentials.json \
  --genesis-sha256 TRUSTED_FULL_GENESIS_SHA \
  --endpoint http://127.0.0.1:RPC_PORT \
  --journal /home/operator/private/original-payment-journal
```

Open the printed local address. Do not use production keys/funds. Native component
measurement is separate from fresh full validator/browser qualification; source
implementation alone does not establish a functional or ready product.

## Disposable two-wallet demo

`tools/p8-wallet/scripts/demo_wallet.py` accepts the same explicit engine, worker,
helper, fixture, prover and public seed KAT paths as the validator qualification
scripts, plus a new `--output` receipt path. Run it in the foreground on the
trusted Linux host. It creates fresh owner-only synthetic state, four local
validators and separate Bob/Carol wallet workspaces, credentials, journals,
session tokens and loopback browser origins. Existing wallets are never loaded
or migrated. Stop with Ctrl+C; all owned servers and validators are closed.

Open the two printed origins. “Load synthetic demo inputs” fills local file paths
and public example payment values; it starts no financial action and enters no
confirmation. In Bob's window, authenticate signed state, import the received
note, authenticate wallet inventory and select its note. Prepare the example
payment, review the original, then type its exact send confirmation.

The demo intentionally drops the real node's admission reply after one forward.
The wallet shows an unknown outcome. In the launcher terminal enter `settle bob`
to let the other two validators commit and capture a signed AS-OF packet. Load
inputs again and reconcile explicitly. Export the exact wire. To deliver the
private opening choose “Private opening” and use a new path named
`recipient-opening` beside that wallet's `exact-wire` output.

In Carol's window, load inputs after Bob's settlement/delivery, authenticate
state, import the exact output and repeat the example payment back to Bob.
Use `settle carol`, then signed recovery. Each wallet has its own one-request
transport budget. There is no automatic broadcast, retry or reconciliation;
reconciliation is an explicit operator action after the dropped reply.
This fixture's plaintext inspection is test orchestration only; the wallet
server itself reads no wallet plaintext and retains protected caller authority.

The actual browser gate is `tools/p8-wallet/tests/browser_native.test.cjs`. It drives
these real UI actions, checks the private review in memory, exercises a deliberate
correct-confirmation replay refusal, and retains sanitized receipts and overview
screenshots only. The preview gate and HTTP unit tests stub the financial child
and remain separately labeled. Qualification requires the native browser gate
and fresh inherited validator journey; neither a screenshot nor a source manifest
substitutes for those results. Production custody, browser/host hostility,
independent operators, current-network freshness and public launch remain open.

## Retained qualification

The [actual browser receipt](../evidence/protocol8-alpha/20261007/alpha-05.json)
captured clean source `8a8dce9a9973db2ccee0a026babddf13f02ea23f` and passed all
ten alpha checks. Its 24 protected console actions cover two separate synthetic
wallet flows. Bob's payment executed, was recovered from a lost reply without a
second attempt, and was privately delivered. Carol imported that exact output,
executed a second payment back to Bob, and recovered its exact execution from
another lost reply. Both deliberate repeated submits refused without additional
transport I/O. The four validators agreed; all owned processes were stopped.
Only cleared overview screenshots were retained, at desktop and 390px widths.

The [closed checker and independent native replay](../evidence/protocol8-alpha/20261007/alpha-independent-replay.json)
validated three distinct public proofs and three signed AS-OF states using the
actual pinned verifier in a separate run. It binds role, original wire, txid,
one-forward proxy, signed execution, source membership and process lifecycles.
The final CLI requires `--worker`; its library's explicit structure-only result
is weaker and cannot serve as native qualification. New receipt regression tests
refuse 51 coherent semantic alterations, including the process/source omissions
found during independent AI review. This is not an external cryptographic audit.

The [inherited fresh guide run](../evidence/protocol8-alpha/20261007/guide-alpha-01.json)
executed clean source `3a699ae94f76399e520138301a3a2965c42c2e14` with the new worker;
its guide, journey, console, payment and wallet gates passed. Its recipient
re-spend remains prepared/exported/natively verified; the second chain execution
claim comes specifically from the separate browser run. The inherited independent
replay checked five proofs and three signed states; 215 altered inherited receipts
were refused. Final focused units passed 150 P8 plus 18 HTTP methods with no skips; the
HTTP financial child is a labeled stub. Coverage tests passed 32 methods. The
whole-current-checkout release suite was not run for this milestone.

The [startup measurement](../evidence/protocol8-alpha/20261007/startup-measurement-01.json)
has three alternating legacy/batch pairs. Their medians were 27.500946096s and
7.744740465s, a 3.550919 ratio in this bounded one-host component sample. Both
logical proof checks and actual parameter/key identities remained required;
malformed/context requests and a wrong binary pin refused, with all workers reaped.
No end-to-end or hardware-independent performance claim follows.

The [successor preservation receipt](../evidence/protocol8-alpha/20261007/successor-preservation.json)
binds the 85 prior protected runtime files to merged PR #85. Exactly
`src/protocol8_worker.py` and `scripts/protocol8_worker_exec.py` change;
the other 83 and all 829 prior historical evidence files retain their bytes.
Native verifier/bridge and additive interface/checker/tests are separately
registered. Historical receipts keep their original captured revisions and are
not silently requalified. Existing configurations refuse the changed pins.

Negative attempts are retained. Alpha01 refused a hard-linked Cargo worker;
alpha02 refused a hard-linked fixture before network startup. Owned single-link
copies with unchanged binary hashes resolved those preflights. Alpha03 exposed a
Windows-to-WSL loopback readiness race; a bounded read-only GET probe now checks
each page before browser actions, without retaining HTML/session tokens or
retrying financial actions. Alpha04 received funds but refused preparation from
an arbitrary 256-bit request outside the protocol field. Canonical nonzero field
generation and a corrected public prepare-state assertion resolved it. Alpha05
passed. No old wallet, global WSL/network configuration or public endpoint changed.

`alpha-native-replay-01.log` retains an initial checker field-path error before
native replay. The next replay passed but its receipt source-member counter used
a shadowed artifact-count variable; that historical receipt is
`alpha-independent-replay-01.json`. The final fresh replay03 and canonical
`alpha-independent-replay.json` correctly report 252 source members. No proof or
acceptance check was removed. Registration/checker changes after the executed
browser revision do not change the executed wallet or native source bytes.

Recheck retained evidence on the trusted Linux host:

```sh
python -B tools/release/check_protocol8_alpha.py \
  evidence/protocol8-alpha/20261007/alpha-05.json \
  --worker /absolute/path/to/owned-pinned-recipient-consensus-bridge \
  --output /new/private/path/replay.json
python -B -m unittest discover -s tests -p test_protocol8_alpha_receipt.py -v
python -B -m unittest discover -s tools/p8-wallet/tests -p test_wallet_app.py -v
```

The checker requires the recorded worker SHA256. Build the bridge from the
captured source using the locked release dependency graph; keep a separately
owned single-link executable for protected callers. Compiled binary reproducibility
across toolchains is not established. The Windows/WSL browser gate additionally
requires the explicitly selected local Playwright driver and browser executable.
