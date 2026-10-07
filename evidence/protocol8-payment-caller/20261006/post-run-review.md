# Completed payment-caller evidence review

Two separate read-only AI peers reviewed the source and completed evidence:
`merchant_authority_review` and `merchant_native_review`. Root independently
ran the receipt checks, tamper cases, separate native replay and owned-process
scan. These are AI peer reviews, not external specialist certification.

Selected fresh execution is `payment-02.json`, source
`a7dc356c640be4f001c5f5772eca35de72e1029e`. All 13 caller checks and 22 inherited
actual wallet checks passed. The report retains 53 wallet and 15 payment CLI
responses, with 16 and 6 intended refusals respectively, and 13 public artifacts.
No forced cleanup was used; the owned proxy and gate workers stopped.

The actual proxy observed wallet attempt1 and journal `attempt-marked` before
forwarding one exact 3,560-byte payment wire. It captured actual node admission
code0 and dropped the reply. The caller retained unknown, rejected repeat/fresh
journal submissions, and recovered signed exact execution without another request.
Both separately recorded fixture broadcasts are distinct from that caller request.
Cold reopen, private recipient import and certified conflict-held passed.

The closed checker binds recovery to the original wire and signed witness fields,
including receipt raw bytes, statement, hash, height, AppHash and genesis. It binds
the held conflict to the original and genuine competitor identities. Both public
journal envelopes and status response hashes agree. All 30 tamper cases refused,
including a counterfeit exact receipt with matching repeated objects and
recomputed raw-stream, invocation and linked-report hashes.

`public-replay.json` independently replayed four distinct native proofs and three
static-quorum signed AS-OF certificates at the same source. All 39 native worker
calls were retained and reaped; no timeout occurred. Both peers read the completed
replay receipt and reported no material inconsistency.

Public receipt consistency cannot recompute journal MACs without the excluded
external wallet key. Certificate authenticity comes from the inherited actual
wallet gate and separate native replay, rather than a new independent signature
verifier in the payment checker. The interruption journal was explicitly
constructed and an actual encrypted-wallet marker persisted; an OS process kill
at that marker was not induced.

The failed run01 is preserved as the original fixture-routing defect, with no
qualification transferred. Corrected fresh run02 alone supplies qualification.
The result remains finite synthetic funds on one trusted Linux/WSL host, AS-OF
only. Freshness, production custody/key management/privacy, backup rollback,
independent hosts/signers, actual marker-kill/power-loss recovery, hostile hosts,
scale, economics, specialist review and public launch remain separate gates.
