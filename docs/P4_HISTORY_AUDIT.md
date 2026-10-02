# Bounded P4 wallet history audit

This development change targets repeated replay of one retained proof during a
single canonical wallet audit. It does not shorten authenticated history or raise
any node, RPC, wallet, delivery, archive or custody limit.

The wallet must still validate every original signing context and exact native
wire, signature, review, nonce lane, invoice expiry, reservation and rotation
pause. An unresolved payment stays held. Full native execution and administrative
authorization are required before any proof can be reused.

Reuse is private to one `_load` invocation, including its custody audit caller.
At most one complete canonical observation BLOB is retained. Policy and exact
genesis bytes are frozen; different proof bytes require full verification. Every
use checks the requested original time against fixed trust and the authenticated
H+1 header's future bound. The full verifier establishes strictly increasing
header times, so this final timestamp bounds all prior headers. Returned objects
cannot mutate the retained proof/report. Failed checks are never cached.

No persistent trust, automatic renewal, cross-operation cache, public report
authority, new journal, protocol/native/snapshot change or delivery optimization
is introduced.

## Local comparison, 2 October 2026

Baseline: `bfbfab6d13332477247ecb8a4cc24378e76f1aa7`, source ID
`9d60b63ebc0299d72dd425951a7eb6acef68b6b51b98bc1ca045959ed093903c`.
The measured candidate's complete file inventory has source ID
`b3e2ea40b338cd70fcabd352e15be36ce831cf1f2b00db9f0d1118256412fd05`;
subsequent documentation and the final committed inventory are separately pinned
in the delivery receipt. Measured production, fixture, verifier and profile bytes
must remain unchanged. Historical qualification manifests are not rewritten as
current evidence.

The workload executes actual native rules with synthetic validator signatures
and publicly known disposable keys. Heights 8/24/48 contain growing positive
receipt histories and respectively 1/8/16 unresolved decisions at distinct
original signing times. Five fresh processes per revision per workload alternate
baseline/candidate order, each with one status warm-up and one measured status.
Both revisions read exactly the same journal and fixed clock. All 30 status
hashes matched their case, and each complete database hash remained unchanged.

| Height / decisions | Baseline median | Candidate median | Reduction | Full proof replays |
| --- | ---: | ---: | ---: | --- |
| 8 / 1 | 59.08 ms | 30.71 ms | 48.0% | 2 → 1 |
| 24 / 8 | 877.80 ms | 154.34 ms | 82.4% | 9 → 1 |
| 48 / 16 | 4692.46 ms | 497.35 ms | 89.4% | 17 → 1 |

The predeclared gate passed: at least 40% median reduction on both repeated-
decision workloads, no more than 20% regression on the smallest case, and
`(max-min)/median <= 0.40` for each revision/workload. CPU time followed elapsed
time. Largest-case whole-process peak RSS was 71,636 KiB baseline versus 50,752
KiB candidate. This high-water mark includes imports, opening and warm-up; it
does not isolate cache allocation or establish a hard RAM budget.

Target: one local WSL2 host, Python 3.14.4, cryptography 46.0.4, protobuf 6.33.6.
An initial comparison could not start because WSL restarted and cleared `/tmp`
fixtures. Its failure and successful initial baseline diagnostics are retained;
the completed comparison used a fresh durable private fixture directory. No
samples were discarded from the completed 30-run comparison.

## Reproduce within the development boundary

Use the already installed pinned dependencies. This script does not install them:

```sh
python -B tools/protocol4-wallet/scripts/profile_history.py \
  --root /path/to/candidate --fixtures /new/private/fixture-directory --prepare
python -B tools/protocol4-wallet/scripts/profile_history.py \
  --root /path/to/baseline --fixtures /new/private/fixture-directory --case 2
python -B tools/protocol4-wallet/scripts/profile_history.py \
  --root /path/to/candidate --fixtures /new/private/fixture-directory --case 2
```

Use a new private directory and the same generated inputs for both revisions.
The complete result contains the frozen contract, exact inputs' metadata, source
inventories, execution samples and counterbalanced runner. Fixture vaults and
wallet databases remain private and are excluded from the return package.

## Remaining scale and release gates

Full receipt-prefix restore/replay cost still grows inside one proof. Delivery
audits and receipt-capsule duplicate replay remain unchanged. RPC collection
still stops above height 64; native P4 height is bounded at 512; read/wallet
observations stop at 32. Complete custody BLOB payload is bounded at 7 MiB, below
some journal capacities. No evidence is pruned or observation evicted to improve
timing, and these figures are development ceilings, not recommended capacity.

This does not establish independent operators, real consensus at this source,
production custody/security, public-network performance, economics, private
payments or launch readiness. Native/registry/consensus bytes are unchanged; an
ancestor engine run is historical evidence only. Current functional/review
receipts and exact final source identity are supplied in the return package.
