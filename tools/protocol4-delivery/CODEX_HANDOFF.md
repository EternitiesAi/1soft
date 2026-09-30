# P4 delivery: exact-base acceptance and publication

Base: PR28 `b73a88ca53666972ae2c8ce35fd9edb7ac0cb41c`, tree
`123e5bfc57d42ee31736969f61aa5a6d32482832`.

The three additive client directories are included. The read-client and wallet
files are unchanged from their previous deliveries; the new implementation is
`tools/protocol4-delivery`. `delivery.patch` applies when those exact dependencies
already exist; `combined.patch` adds all three to a clean PR28 checkout. Verify the
complete dependency inventories before applying either. Do not merge parallel
PR29 recovery work automatically or overwrite a different client implementation.

`dependency-slice/` is only the exact32-file native/helper/dependency input needed
for these isolated client tests. It is NOT a complete PR28 node, root inventory,
release checkout or engine runner. Do not install the slice over an existing node.
Use the actual repository for full-release and engine work.

## One exact clean candidate

Run the three separately registered suites and full existing release profile.
The old release checker does not automatically discover these client add-ons:

```sh
python tools/protocol4-client/tools/verify.py --native-root . --report ../new-read.json
python tools/protocol4-wallet/tools/verify.py --native-root . --report ../new-wallet.json
python tools/protocol4-delivery/tools/verify.py --native-root . --report ../new-delivery.json
python tools/release/check_release.py --output ../new-whole-release
```

The new delivery suite has65 cases; read97 and wallet76 are separate unchanged
components. Do not add old reports from different revisions to call the candidate
qualified. Re-run the existing P4 full-response Go oracle and real engine baseline
against the supplied genuine CometBFT0.38.25 executable with its independently
recorded SHA-256. Missing binary/dependencies are unassessed, not replaced by fixtures.

## Real engine delivery acceptance

On a disposable, locally routed P4 network and externally pinned client policy:
initialize the supported P4 signing journal; sign two grants against one shared
budget, including an overcommit that must refuse before unlock. Use **P4Delivery**
to prepare and send the first existing decision through a loopback proxy that drops
the downstream response only after upstream successful CheckTx. Admission is not
execution: collect signed evidence and require the exact native receipt later.
The actor labels in synthetic demos do not establish real autonomous-agent work.

Confirm exactly one submitted original wire. Reopen the transport and signing
journal. Receipt collection must leave all logical wallet rows/holds unchanged.
Only explicit reconcile with the exact wallet revision may reduce the matching
hold. Then execute an authorized full validator turnover, import its evidence into
the wallet and verify that the second original wire/hold remain. Deliver the second
original wire under the new roster, collect, and reconcile. Revisit the earlier
receipt at the later wallet checkpoint; it must return already_recorded without a
rollback or duplicate release. Compare conserved account/budget/fee arithmetic
against the actual genesis and setup, not assumed demo balances.

Also exercise real subprocess exit after claim-before-I/O, after submission-before
response retention, and after wallet sync-before-return. Unknown dispatch stays
unknown and cannot be resent through this journal. A network decline must neither
retire the hold nor allow another attempt. Keep wrong payer/grant, stale review,
changed endpoint/config, invalid proof, expired trust and legacy P4 refusal tests.

This intentionally has no retry/rearm/reset path. If a claim commits but the process
dies before I/O, that decision may stay unresolved. Do not call it a successful
submission, create a replacement signature or new journal to manufacture progress.
Any liveness extension requires a separately reviewed exact-attempt policy.

P4 node bootstrap/Commit crash, independent hosts, production keys/custody, security
review, customer UI and public governance/economics remain separate. One-host
engine evidence does not establish those gates.

## Return and publish

Retain all failures and exact passing IDs/logs, source/tree/file identities,
engine/oracle results, original public wires/evidence, count of actual submissions
and staged reservation observations. Exclude keys, passwords, wallet/node DBs and
unneeded personal paths. Publish one new draft branch after exact-source checks;
no force-push, merge, Actions, paid/public compute, deployment, DNS/site, Resident/
Luna/Psyche work, real funds or production keys.

This authoring run had read-only GitHub actions available, so no new remote source
or PR was created. Its full PR28 runtime slice is byte-verified; it does not claim
to include or rerun PR28's complete checkout or Windows-only engine return ZIP.
