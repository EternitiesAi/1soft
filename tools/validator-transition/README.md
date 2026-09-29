# 1soft validator-transition foundation

Read-side validator evolution and unsigned transition planning on exact PR #23,
289a78056b86ebdd5878d285027f5c78562e0767. This component is isolated from the current
native node, signing wallet, explorer, receipt archive and state-sync application.
The original static verifier remains byte-for-byte unchanged and still rejects
validator changes. No protocol 4 or changing-validator chain is enabled here.

## Implemented interfaces

`ValidatorSet.parse` validates canonical complete sets. `validator_updates` computes
a deterministic delta. `draft_transition` describes the H/H+1/H+2/H+3 timeline and
explicitly says authorization is not established and activation was not performed.
It produces no transaction. `validator_wire.encode_update_response` is only a
protobuf compatibility probe for the update field.

`start_witness` verifies an external checkpoint pin. `extend_witness` requires the
exact parent proof digest and returns a new verified proof without changing the
old object. `verify_witness` checks every original signed header, signature slot,
current/next roster commitment, complete parent block identity and height/time
continuity. No roster from a peer can override those hashes. Whole-roster replacement
is verifiable with contiguous authenticated headers; no skipped-block or trust-period
shortcut is implemented. `audit_transition` checks a planned isolated roster timeline,
not governance authorization, node response emission or full block validity.

Policy expiry is fixed at original anchor time plus the operator-supplied interval.
Receiving newer headers never renews it. Proofs preserve historical bytes on refusal;
no timeout releases money or chooses a competing chain. The verifier does not read
native balances or clear pending wallet commitments. It is not an alternative wallet.

## Commands

With the repository's pinned dependencies already installed, no downloads needed:

```sh
python tools/validator-transition/tools/verify.py --native-root .
python tools/validator-transition/scripts/demo.py --output ../new-transition-demo
python tools/release/check_release.py --output ../new-full-local-results
```

The demo uses public deterministic validator keys and synthetic signed headers,
not live consensus or actual governance transactions. Its AppHashes are labelled
fixture commitments, not native execution results. It writes no private keys. The
proofs are timestamped when the demo is produced and deliberately expire; they
are not evergreen financial evidence.

For explicit input files:

```sh
python tools/validator-transition/scripts/transitions.py \
  --genesis ENGINE_GENESIS.json --policy EXTERNAL_POLICY.json \
  start --entry ANCHOR_ENTRY.json --output NEW_PRIVATE_WITNESS.json

python tools/validator-transition/scripts/transitions.py \
  --genesis ENGINE_GENESIS.json --policy EXTERNAL_POLICY.json \
  extend --witness OLD_WITNESS.json --entries NEXT_ENTRIES.json \
  --expected-parent-sha256 EXPECTED_OLD_DIGEST --output NEW_PRIVATE_WITNESS.json
```

The same CLI supports `draft`, `verify` and `audit`; help lists required fields.
Output parents must be private owned POSIX directories; outputs never overwrite.
No activate, sign, broadcast, network-refresh or node-configuration command exists.
The policy must come from an independently trusted source; copying the policy and
proof from one untrusted endpoint does not create trust. Native JSON units, signed
transaction bytes and all protocol 1/2/3 AppHash formats remain untouched.

## Upstream agreement gate

The bundled Go probe imports exact CometBFT v0.38.25. With its dependencies already
cached, run from `tools/validator-transition/upstream`:

```sh
GOPROXY=off GOTOOLCHAIN=local go run . < /private/demo/upstream-vectors.json
```

It compares multi-validator hashes, the result of applying the update delta, and
the FinalizeBlock update protobuf bytes against the Python-generated vectors.
This is a compatibility probe, not a validator network. Missing cached modules are
unassessed; neither a syntax-format check nor old wire results replace execution.
No automatic dependency install is part of the local release profile.

The precise unfinished activation, governance, native-state, wallet and state-sync
contracts are in docs/proposals/SIP-0002-validator-transitions.md. This is a working
verification foundation, not the completion of validator-set evolution as a live
protocol. Independent operators, external security review, custody, economics and
public/real-funds readiness remain separate. No Actions, paid compute, public
service, DNS/site or Resident/Luna changes are involved.
