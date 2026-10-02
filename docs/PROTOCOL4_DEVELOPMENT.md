# Fresh-genesis protocol 4: development boundary

Protocol 4 is an opt-in development chain, separate from the existing P1/P2/P3
applications and from the registry-only app version 4001. It does not migrate an
existing chain. Its genesis binds native monetary parameters and the SIP-0003
validator registry in one canonical digest. Native payment signatures and
administrative authorizations each bind that full digest. Administrative approval
never grants spending authority.

`src/protocol4_application.py` keeps native balances, budgets, grants and receipts
beside registry epoch, active/next rosters, queue, sequence and receipt head.
CheckTx and proposal processing are speculative. FinalizeBlock validates the
engine's next-validator commitment and last-commit roster; Commit writes the
composite state, exact transaction wires and full response in one SQLite
transaction. Its domain-separated AppHash covers the native snapshot and registry
state. A restart replays the retained transaction inputs. The most recent locally
committed FinalizeBlock can be returned byte-for-byte only for the same request
identity; a conflicting replay is refused.

The separate `scripts/serve_abci_p4.py` speaks pinned CometBFT v0.38.25 ABCI++.
The disposable one-host runner checks a payment before a signed roster schedule,
H/H+1/H+2/H+3 validator hashes and votes, removal, one restart, and a payment
after turnover. Local process-exit tests cover both sides of the SQLite Commit.
This is narrower than independent-host or Byzantine qualification.

Format-2 P4 state sync carries composite state plus bounded replay inputs. A
recipient must have the exact expected P4 genesis and an AppHash independently
verified by CometBFT's light client. It re-executes retained transactions and
installs state atomically only if they reach that AppHash. Queued, emitted and
activated transitions are tested. Peer-supplied historical block identities,
votes and FinalizeBlock responses are **not** imported as authenticated evidence.
A snapshot-bootstrapped node cannot answer historical `/block/H` queries for
those heights; new local blocks have exact response records. Snapshot history is
a state-replay input, not a signed-header archive. Complete history and a 16 MiB
ceiling limit this to bounded development networks; no pruning plan exists.

The static validator trust anchor, certified wallet, legacy signer, explorer and
receipt archive reject P4. Separate P4 read, signing-wallet and decision-delivery
adapters now validate signed dynamic-validator ancestry and full native execution.
See [their exact-source acceptance gate](P4_DELIVERY_ENGINE.md). They do not add
an explorer, portable receipt-capsule standard, public RPC or production custody.
Governance key recovery/rotation, long-outage cancellation, independent operators,
economics, production security and real funds remain outside this experiment.
