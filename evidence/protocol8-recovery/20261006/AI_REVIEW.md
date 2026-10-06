# P8 recovery review and evidence scope

Two separate read-only AI peers reviewed the recovery trust/store boundary and
the actual-engine caller/receipt gate. Initial review identified post-commit
stale-memory service and missing origin-prefix enforcement; both were fixed before
qualification. Final source reviews reported no remaining concrete defect in
their bounded review. This is not external specialist certification.

The selected fresh-network run is `state-sync-04.json`, executed at clean source
`dab1f071be58191e7eda7672a7944c18ed5a3a26`, tree `229cc0b3f2eadf2a5345269056b226a88a89b9f3`. All22 actual checks passed:
four fresh validators, one fresh nonvalidator, genuine recipient receive/spend,
Comet light-client snapshot offer, exit96 after durable import before final Apply,
same-store engine re-offer, exact full-state replay, no fabricated responses,
ordinary rejoin, one wallet broadcast, signed exact settlement and target restart.
Raw callback identities and actual Comet Verified ABCI/Snapshot restored logs are
retained. Independent public replay verifies both native proofs, both signed state
witnesses and both H+1/H+2 provider headers.

Eleven labeled fake-worker recovery tests and eleven original lifecycle regressions
passed with no skips. Six upstream Go snapshot codec comparisons passed from
cached read-only modules. Sixteen deliberately altered receipts were refused;
receipt checks are separate from native proof/consensus execution.

Run01 at `2d7a001e53530add9950bb345e40db754202c592` genuinely imported/crashed/re-offered
and verified state, then failed with KeyError3 during source-peer reconnection:
the helper expected a paused validator to be running. That owned-runner ordering
was repaired. Run02 at `f1b4ffb844945a2c6aad44cea0cf0d43e3a6cc3b` recovered/rejoined,
then its wallet correctly refused an invalid test intent whose valid-until60
exceeded payment-expiry56. The intent was corrected to valid-until56 without
changing wallet guards. Run03 at `bc7ee08a235a823915288ae1cb053dff018567c1`
passed actual payment/certificate/reopen, then the final test compared its public
SQL origin marker with an accidentally overwritten private note-origin variable.
Distinct variable names and explicit public marker evidence fixed the assertion;
checks were preserved and strict event ordering/raw-event/log binding strengthened.
Entirely fresh run04 qualified. All three failed report/log/artifact sets remain
in the delivery ZIP and private output directory; they are not qualified.
An early fake-worker schema test also opened a still-locked target; closing its
owner made the test exercise the intended schema boundary. The first committed-
inventory helper invocation lacked its required repository argument, then the
correct invocation verified all558 entries. Neither was a product pass.

Original P1–P7 and frozen P8 relation/profile/consensus/application/dispatcher/wallet
bytes are preserved. Recovery is a separate schema/server, with no silent store
migration. Qualification is finite on one trusted host with synthetic notes;
validator signing-state recovery, independent operators, production light-client
policy, hostile hosts/networks, freshness, pruning/scale, power-loss durability,
privacy/custody, economics, external review, public deployment and real funds
remain unassessed. No Actions, paid/public compute, website/DNS or other-project
work occurred. All measured native children were reaped and owned engines/apps
stopped. Crashed-process audit counters are unavailable; totals describe retained
measured receipts, not an invented complete count of all executed native work.
