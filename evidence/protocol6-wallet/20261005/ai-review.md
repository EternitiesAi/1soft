# Read-only AI peer review

Source: c0b442868a14a9adfffd3be4215135656a39e9b4.
Reviewers: treasury_worker_review and treasury_consensus_design_review.
Scope: source/journal/certificate/transport/CLI and completed actual runner receipt;
reviewers made no edits and launched no proof or validator jobs.

Material findings repaired before qualification:
- First claim after an authenticated conflict/stale state or elapsed window was
  possible. Two failing tests reproduced this. Claim now checks latest authenticated
  resolution/window within the same atomic transaction before persisting an attempt.
- Default urllib followed redirects from the approved loopback endpoint. A real
  local HTTP test reproduced a second GET. Transport now refuses every redirect,
  disables proxies, closes HTTP-error responses and performs no second request.
  Six destination variants including externally named and IPv6 targets are refused.
- Explicit source coverage now includes the new wallet, transport, runner, CLI and
  checker even in dirty candidate runs. Qualified tracked source already used the
  inherited broad source capture; no omitted-source qualification occurred.

Final source review found no remaining material one-attempt, acceptance or local
transport flaw. The completed receipt binds19 passing checks,17 raw artifacts,
four applications/four validators with captured exits, exact bootstrap and worker
identities, state height1 authenticated by height2 with30/40 voting power, exact
payment completion/reopen/export and conflicting obligation held with0 attempts.
Acknowledgement loss is an intentional injection after an actual RPC acceptance.
Zero-byte application logs are preserved; structured startup/process/certificate
and engine artifacts provide the stated evidence. No substantive app log is invented.

The reviewers maintain the bounded one-host finite controller claim. This is
AI peer review, not independent specialist cryptographic/protocol/custody audit.
Trusted POSIX host, static grants/quorum, no freshness, hostile-host rollback,
cross-device coordination, proving/custody, real funds or public deployment.
Owner lifecycle requires a new proof/profile with signature-governed context,
owner sequence/key commitment and grant generation; no local P6 wrapper suffices.
