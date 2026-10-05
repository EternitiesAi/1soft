# P7 exact owner/payment client

This optional successor client retains prepared owner commands and payment proofs
in one private POSIX FULL-sync WAL SQLite journal. It does not sign or prove.
Original P7 kernel, application, service and P1-P6 bytes are preserved. Current
source is a candidate until its actual client report is registered and checked.

`scripts/owner_treasury_wallet.py` requires explicit full genesis SHA256, measured
worker SHA256 and the exact network-domain KAT. Commands are `retain`, `inspect`,
`observe`, `export`, `deliver-once` and `record`. Observations contain exactly
`witness` and `signed_header` in canonical JSON. Prepared transactions are the
original canonical signed/proved bytes; export never authorizes a retry.

One context/owner-sequence/input/parent/grant/request resource can have one live
local obligation. Claim inserts a permanent attempt before transport. HTTP is
one bounded loopback call, with proxies and redirects disabled. Returned errors,
lost replies and code0 do not prove execution or clear a hold. Only exact typed
inclusion in an independently replayed full-state/quorum certificate completes
an obligation. Reopen audits retained wire, resources, identity, attempts and
certificate history. Rotation/revocation/conflict or a stale/elapsed observation
refuses an unattempted transaction before any delivery.

An actual COMMIT for header H+1 authenticates application state H. That block
already exists, so a fresh transaction cannot execute before H+2. An unseen H+1
application update can still stale the AS-OF context. The optional companion
`scripts/serve_abci_p7_admission.py` admits an owner command up to eight future
heights while validating its current signature/CAS. It neither synthesizes
blocks nor commits successors. Original exact-height proposal/finalization rules
remain authoritative. This is local mempool policy, not a new proof/profile rule.

Run `scripts/run_protocol7_client.py` with explicit pinned engine/worker/prover,
synthetic template and fresh output. Its checker is
`tools/release/check_protocol7_client.py REPORT --worker VERIFIER`. Actual future
owner admission, early proposal refusal, exact-height owner execution, two lost
acknowledgements, typed certificate recovery, stale first-claim refusal and
ordinary same-store restart are required before qualification.

The finite controller is one-host development evidence only: eight obligations,
65 observations, 1MiB observation packets, 64-block kernel history and no eviction.
No freshness, malicious-host rollback protection, cross-device coordination,
automatic retry/migration, production custody, public operation or real funds.
