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

Each server has a fresh in-memory session token, exact127.0.0.1 origin/Host checks,
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
transport budget. There is no automatic broadcast, retry or reconciliation.
This fixture's plaintext inspection is test orchestration only; the wallet
server itself reads no wallet plaintext and retains protected caller authority.

The actual browser gate is `tools/p8-wallet/tests/browser_native.cjs`. It drives
these real UI actions, checks the private review in memory, exercises a deliberate
correct-confirmation replay refusal, and retains sanitized receipts and overview
screenshots only. The preview gate and HTTP unit tests stub the financial child
and remain separately labeled. Qualification requires the native browser gate
and fresh inherited validator journey; neither a screenshot nor a source manifest
substitutes for those results. Production custody, browser/host hostility,
independent operators, current-network freshness and public launch remain open.
