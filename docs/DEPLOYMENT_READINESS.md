# 1soft deployment readiness

Target: a coherent private economic-authority cryptocurrency/payment product.
Current qualification is an owned local development environment with synthetic
funds. It is not an approval to operate a public value-bearing network. Existing
authorization covers development, local verification and private-repository
merges; public/paid compute, deployment/DNS/site changes, real funds, production
keys and other projects remain excluded.

## Observable finish conditions

A developer release needs reproducible source identity, real-engine receipts,
actual client recovery, bounded resource/fault behavior, preserved compatibility,
source/reuse notices and exact run/recovery instructions. Each receipt states
its covered revision and does not inherit older profiles' evidence.

An independent operator rehearsal additionally needs approved hosts and pinned
bootstrap custody, peer/admission and monitoring configuration, restart/partition/
upgrade/rollback drills, retained history and operational ownership. One-host
tests cannot close that gate.

A public value-bearing launch also needs a complete selected production proof/
privacy model, safe wallet/note custody and recovery, authenticated owner/grant
lifecycle, recipient and merchant redemption, scaling/pruning, independent
specialist review, reviewed software supply chain and explicit economics/genesis/
governance. External service or legal/partner claims require actual agreements.
No ticker, listing, investment return or reserve promise follows from code tests.

## Current gate map

| Gate | Evidence now | Remaining condition |
|---|---|---|
| Exact source and historical protocol preservation | Required-source manifest and private merge receipts | Recheck each material revision; never reset old evidence |
| P6 atomic private payment/shared allowance | Registered19-height state authenticated by20-height header; all18 actual engine checks | Finite64-height/16-note profile, static grants and one host remain |
| P6 exact certified client recovery | Registered clean-source19-check actual engine receipt, exact completion/reopen and actual proof/CLI/adversarial tests | Local finite controller only; freshness, custody and independent operators remain |
| One-attempt local delivery | SQLite attempt committed before bounded loopback RPC; explicit acknowledgement discard test | One canonical journal only; no hostile-host rollback or cross-device guarantee |
| Owner grant lifecycle | P7 fresh network-bound proof profile; registered rotation/revocation, reactivation and enrollment,17 actual checks per run | Custody/key recovery, independent review and operators remain |
| P7 typed client/caller recovery | Registered25-check actual future-owner/payment run; two discarded acknowledgements recovered from exact certificates; stale first claim refused | Typed client and prepared wire; note custody/discovery/redemption remain |
| P7 bounded proof preparation | [Registered16-check actual arbitrary-payment run](../evidence/protocol7-prover/20261005/prover-qualified-01.json), strict replay checker and4 adversarial receipt tests; exact profile/verifier-only consensus bridge retained | Canonical developer inputs and synthetic openings on one POSIX host; merchant redemption/discovery and production custody remain |
| P7 encrypted restricted CHANGE custody | [Registered24-check actual import/re-spend/reopen gate](../evidence/protocol7-vault/20261005/vault-qualified-02.json), exact CLI recovery, precise spent/revoked guards and strict replay | One host, external key, finite synthetic notes; rollback/key recovery, discovery and merchant redemption remain |
| P7 retained authority, status and restart | [Complete36-check v2 actual gate](../evidence/protocol7-reconciliation/20261006/reconciliation-qualified-04.json), strict proof/certificate replay and 20 early tamper subcases; three payments and five read-only snapshots | One host/external key; no retry/latestness authority; standalone 30 recipe unqualified |
| P7 certified local merchant fulfillment | [Registered 26-check actual gate](../evidence/protocol7-merchant/20261006/merchant-qualified-03.json), independent public replay, five actual merchant calls and 19 early tamper subcases | Explicit trusted-local disclosure and external key; merchant redemption, public integration and independent private decryption remain |
| Notes, recipient discovery and redemption | Earlier isolated proof laboratories and P5 finite wallet remain distinct | P7 encrypted note discovery/disclosure/redemption and custody must compose with its certified journal and prover |
| Scale/history/availability | Deliberately finite profiles and replay | Scalable authenticated pool, receipt availability/pruning and measured resource bounds |
| Production privacy/security | Specific relation/worker tests only | Independent cryptographic/protocol/custody audit and privacy threat model; no production claim |
| Independent operator network | Not established | Separately owned hosts, bootstrap custody, network fault/security/operator drills |
| Supply chain and operational release | Pinned source/binaries/dependencies and existing NOTICE | Reproducible signed release, review/update policy and operator incident/rollback drills |
| Economics and public launch | No value-bearing genesis or network established | Supply/denomination/distribution/governance and release-owner choices; approved public targets and external review |

## Frontier direction check

Frontier check: 2026-10-05 | sweep: 2026-10-05-sweep.md@8f8b7fa5db4d559c9441936022d2511209059957 | lane: 1soft | result: preserve private/native treasury; extend existing commerce adapters after safe P7 proving/custody, with identity, authority and provider evidence kept separate.

See [the revised mission and development sequence](FRONTIER_DIRECTION_20261005.md).
The native P4 x402 envelope already exists; external-route acceptance and AP2
mapping remain separate integration gates. No new runtime gate passed in this check.

Frontier checked again 2026-10-06: no Oct 6 sweep was committed at inspection.
The Oct 5 sweep revision remains `8f8b7fa5db4d559c9441936022d2511209059957`;
`2026-10-05-agent-finance-watch.md@062cc88b55a53b85ac45f8d85701c62c52a23282`
was also consulted. Its exact authorized-resource/execution boundary supports
precommitted quotes and distinct native/identity/adapter authority. The primary
[x402 canonicalization change](https://github.com/x402-foundation/x402/commit/606ced026102a16d7724125c6b60d93e3ead770b)
was verified as research; no acquired code or external integration was activated.

## Next executable work

P7 owner lifecycle and typed owner/payment recovery are registered in
`evidence/protocol7-owner/20261005` and `evidence/protocol7-client/20261005`.
Bounded arbitrary-input proof preparation is now registered in
`evidence/protocol7-prover/20261005`, covering clean execution source
`ad4d011c93c58da19ed83cedbe01051ce46f59d7`. All16 actual four-validator
checks and the strict receipt checker pass.

Encrypted authentic restricted CHANGE custody is registered in
`evidence/protocol7-vault/20261005`:24 actual four-validator checks at clean
execution source `829c2bc80219a9f1191061775ade3e9362a3e9a4`, strict replay and12
receipt tamper subcases pass. The external-key vault imports exact certified
origins, encrypts future openings before proof retention, re-spends through the
protected-stdin caller and recovers the original wire without proving again.
Owner sequence remains provenance. Spent and revoked-grant refusals are exact
guards; merchant outputs retain their separate domain. This is a finite trusted
host developer custody result, with no rollback or production privacy claim.

Retained private authority, read-only preparation status and authenticated full-
state restart are registered in evidence/protocol7-reconciliation/20261006.
The actual36-check v2 run at clean source `c0e0e7b15921a2d6f0723575f33771eaae724ecf`,
strict replay and 20 early-tamper subcases pass. CHANGE 7 -> 4 -> 1 composes with
five exact AS-OF status snapshots and a post-restart signed H+1 header. The
readiness/convergence budgets and default cap 8 remain unchanged. Earlier failed
and interrupted runs remain preserved; standalone 30 remains unqualified.

Certified P7 disclosure and exact local fulfillment are now registered in
`evidence/protocol7-merchant/20261006`: 26 actual engine checks, strict public
replay and 19 early report-tamper subcases pass. The merchant commits to exact
public resource bytes before payment, verifies all five domain 604 opening terms
against the exact certified wire, encrypts the disclosure and re-verifies after
cold open. A discarded application response recovers the same retained local
result without another wallet attempt. Public replay does not independently
decrypt the ciphertext; this remains explicit trusted-local disclosure.

The [next native value-transfer gate](RECIPIENT_SPENDING_BOUNDARY.md) is recipient-controlled spending and its
recipient custody/recovery design. Current ordinary/CHANGE inputs do not by
themselves authorize spending domain 604 notes. This needs a separately versioned
relation/profile/state/client change and new actual-engine qualification; never
reinterpret P7 commitments or silently import another profile's authority.
Merchant redemption, scalable authenticated history, threshold/key recovery,
economic/genesis/governance and independent operators remain separate gates.

Keep the campaign active while an in-scope implementation/verification gate is
ready. Record completed increments and the next action in repository records and
the private session checkpoint. No background executor or scheduled work is
implied by a saved plan. An external operator, specialist audit, economics or
new publication/spending boundary must be named explicitly when reached.


## P8 recipient component boundary

[Recipient-controlled notes](PROTOCOL8_RECIPIENT.md) now have a separately
qualified native receive/re-spend relation and bounded replayed state kernel.
The synthetic [24-check receipt](../evidence/protocol8-recipient/20261006/recipient-qualified-02.json)
and public replay are native-component evidence. A subsequent separately versioned
[P8 validator application](PROTOCOL8_RECIPIENT_CONSENSUS.md) now has a
[19-check four-validator receipt](../evidence/protocol8-validator/20261006/recipient-validator-01.json)
and separate native/certificate replay: receive/re-spend, valid conflict refusal,
ordered dependency proposals, atomic persistence, same-store restart and signed
AS-OF full state. The static certificate is for state height 3/header height 4;
it establishes no freshness. The subsequent [P8 encrypted recipient wallet](PROTOCOL8_RECIPIENT_WALLET.md)
has a [22-check actual receipt](../evidence/protocol8-wallet/20261006/recipient-wallet-02.json):
signed exact receive import, encrypted cold reopen, arbitrary native preparation,
discarded-broadcast-reply exact recovery, private recipient delivery and genuine
certified conflict holds. The wallet has no network dispatcher or automatic retry.
The separate [P8 node recovery](PROTOCOL8_RECOVERY.md) now has a
[22-check actual state-sync receipt](../evidence/protocol8-recovery/20261006/state-sync-04.json),
covering real light-client callbacks, durable snapshot lost-reply/re-offer,
no invented responses, genuine post-sync recipient spending and same-store
reopening. The imported origin stays outside AppHash and audits only real local
responses after origin. Production custody, signer recovery, independent hosts,
pruning/scale, economics and specialist review remain gates. No P7 migration,
owner-allowance composition, freshness or launch readiness is inferred.

The [protected P8 application workflow](PROTOCOL8_OPERATOR.md) wraps explicit
configuration pins, new private workspace creation, read-only static diagnosis,
native store audit and foreground owner-only ABCI service. It provisions no engine
or keys and chooses no remote trust. Its fresh actual caller/recovery gate must
pass at a clean named source before this integration receives qualification.
