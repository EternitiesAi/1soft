# P4 clients and local engine acceptance

The three additive components are `tools/protocol4-client`,
`tools/protocol4-wallet`, and `tools/protocol4-delivery`. Their supplied trees
are preserved exactly from the P4 delivery handoff on PR28 `b73a88c`.
The separate PR29 node-recovery work is not incorporated by this branch.

The read client verifies the complete bounded signed-header chain and replays
native payments plus authorized validator changes. The wallet signs a reviewed
transfer and durably reserves its amount plus fee before returning the signature.
Delivery accepts that recorded decision, claims one attempt before I/O, and sends
the original bytes. A CheckTx response is an endpoint observation, not execution.
Collection stores verified positive execution evidence only in the delivery journal.
Explicit wallet reconciliation is the operation that can release a matching hold.

The original component READMEs document the full trust and operating constraints.
The clients accept only literal loopback endpoints. A crash after attempt claim
but before I/O can leave an unsent transfer unresolved indefinitely. This version
has no retry, reset, rearm, cancellation or replacement-signature path. Separate
journals/devices are not coordinated; the model is not globally exactly-once.

## One clean candidate

Run these separately: the existing release profile does not discover the new
components. All output paths must be new and outside the checkout. Use the
already-installed pinned Python dependencies from `requirements.txt`.

```sh
python tools/protocol4-client/tools/verify.py --native-root . --report ../read.json
python tools/protocol4-wallet/tools/verify.py --native-root . --report ../wallet.json
python tools/protocol4-delivery/tools/verify.py --native-root . --report ../delivery.json
python tools/release/check_release.py --output ../whole-release
python scripts/run_protocol4_engine.py --engine PATH_TO_COMETBFT \
  --engine-sha256 INDEPENDENT_BINARY_SHA256 --output ../baseline/result.json
python scripts/run_protocol4_delivery_engine.py --engine PATH_TO_COMETBFT \
  --engine-sha256 INDEPENDENT_BINARY_SHA256 --output ../delivery-engine
```

The last runner requires genuine CometBFT 0.38.25; there is no fixture fallback.
It creates four initial validators and four candidate validators on one host.
All RPC/P2P listeners are loopback and generated keys/databases remain inside
an automatically cleaned private temporary directory. The returned directory
contains public genesis, explicit local trust policy, original signed wires,
receipt evidence, staged wallet observations, actual submission counts, and
sanitized bounded process logs. `source_qualified` requires clean unchanged HEAD
before and after. The report, not this document, records execution outcomes.

## Acceptance behavior

The fixture genesis gives the payer 1,000 development units and charges fee 2.
Six setup operations create two budgets and four grants, consuming 12 in fees.
The principal grants share a 100-unit budget: Raven signs 58+2 and Atlas signs
38+2. Atlas 39+2 must refuse before unlocking a key. Signing vault files for these
two grants are removed before any delivery phase.

A forwarding proxy drops the first downstream reply only after the real engine
reports successful CheckTx. A child then exits before response retention. Reopened
journals must retain unknown dispatch and refuse another send. The collector must
obtain the exact execution receipt and leave all logical wallet rows unchanged.
Another child exits after explicit wallet sync commits; reopening must recognize
the existing receipt without a second release.

An authorized schedule replaces all four validators. Signed headers and H+3
commit votes must agree on the replacement roster, and the chain must advance
after all original validators stop. Wallet import must preserve Atlas's original
wire and 40-unit hold. Delivery, collection, and explicit reconciliation complete
Atlas's payment. Revisiting Raven's earlier receipt at this later checkpoint must
return `already_recorded`, preserving every wallet row.

The principal flow must submit exactly two original wires. Its balances are payer
888, merchant 96 and fee account 16; studio budget spent is 100 and pending is 0.
These numbers are checked against actual genesis/setup, including total supply.
Two separate diagnostic grant decisions then exercise claim-before-I/O exit
(zero transmissions) and actual engine rejection after transaction expiry
(one transmission). Both keep their three-unit holds and cannot be retried.
Total proxy submissions are therefore three, of which only two execute.

The component suites retain wrong payer/grant, stale review, changed endpoint or
config, invalid proof, expired trust and legacy-client refusal coverage. The engine
runner is a client acceptance test. Node bootstrap, final Commit reply crashes,
independent hosts/operators, production custody, independent security review,
public economics/governance and customer UI remain separate gates. No deployment,
Actions, public compute or real funds is part of this workflow.
