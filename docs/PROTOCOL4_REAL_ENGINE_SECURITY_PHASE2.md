# Protocol 4 real-engine security qualification, 4 October 2026

Two fresh Protocol 4 state-sync profiles completed with the exact pinned
CometBFT 0.38.25 binary and then passed the separate semantic validator. This
closes the one-host real-engine gate for the exact source content tested. It does
not qualify later source changes automatically.

## Exact source and engine

- source commit: `27a909f2bdceaaae7623394a6791413aff0a7657`
- source tree: `5254048de0933dd3b379257783f81380bb45d48c`
- GitHub merge containing that tree:
  `9e53827518b7b6d6333f9fed392dfd63f55f490b`
- engine: CometBFT 0.38.25
- engine SHA-256:
  `218628da07bed5d27e178d38d0bef9ecf46f21b214c8e9fea402fd215fccc024`

The runs used four fresh source validators and one fresh target on loopback with
disposable development keys. An external controller recorded the actual return
code, timeout and truncation flags, process identity, cleanup outcome and
surviving-process count. The repository's standalone semantic validator then
checked the retained private originals against independently selected genesis,
policy, process and engine pins.

## Results

| Profile | Semantic status | Required checks | Verified headers | Final height | Signed payments | Public result SHA-256 | Semantic result SHA-256 |
|---|---|---:|---:|---:|---:|---|---|
| `basic` | passed | 12 | 15 | 14 | 2 | `5a818048a69f4b1b614f74bcac77d24dfdd332ad365e25d3d42c24624cc1c59b` | `1fe75339eacd2539077e457e1eb59bd3b523b205b413111cadc35bad1333e2e7` |
| `final-apply-crash` | passed | 18 | 20 | 19 | 2 | `269b3724ca48eb3a9a743bbeef1ae60bdb1f6d1b7639822f7a0db3edb78d65d5` | `b0b03aec86675b5ab8867f712d1b8c7254b2a7d0dacb49b72a128af48e36ccd8` |

The external controller receipt SHA-256 values are:

- `basic`: `8b6093ea1d569d01ff1fbd914bad9c99136bdf86d739141cbd08e156d2a6c6df`
- `final-apply-crash`: `52df069d6d7a73aa618ea92d6f152cf50356a4983d400800d9b09be7c11e2abd`

The basic profile validated the 12 common source identity, real-consensus,
fresh-target, fixed-trust, format-2 transfer, AppHash, signed-history,
composite-effects, marker, continuation, policy and process-outcome checks. The
crash profile additionally validated durable commit before the interrupted
final-Apply reply, observed child termination, same-store restart, snapshot-only
restart audit, checkpoint reoffer recovery and rollback-refusal continuation.

The public projection deliberately retains the runner status
`completed-awaiting-external-validation`; it is immutable runner output. The
separate semantic artifacts are the final evidence and both say `passed`.

## Boundary

This evidence applies to the exact pre-phase-two tree above. The new
authenticated-reconciliation and opt-in device-fencing modules do not alter
consensus execution or state-sync code, but their own unit and integration tests
are separate evidence. A later consensus or state-sync change requires fresh
engine runs.

These receipts establish only the registered one-host loopback scenarios. They
do not establish independent operators, multi-host networking, public peer or RPC
hardening, production custody, economics, a public testnet, exchange readiness,
or mainnet readiness. The raw private directories contain disposable keys,
databases, proof payloads and logs and must remain private.
