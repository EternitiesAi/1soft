# P8 operator workflow review and evidence

Two read-only AI peers reviewed the operator trust/filesystem boundary and actual
caller/lifecycle seam before the execution source was frozen. The wrapper keeps
doctor, native audit, foreground serving and engine ownership distinct. A separate
post-run receipt/artifact review supplements this review; none is external
specialist certification.

The fresh actual run is `operator-02.json`, source `c578fee39a484c02328a824c45d107ea43bbc14e`.
Eleven operator checks and the unchanged 22 real recovery checks passed. Five
workspaces used actual CLI init/doctor, normal application lifecycles used the
operator serve command, duplicate ownership and an incorrect external pin refused,
and all five stopped stores were audited through actual native replay. The
test-only crash/re-offer server remains separate from the production CLI.
The real journey includes genuine recipient receive/spend, interrupted snapshot
import, actual light-client recovery, exact signed payment receipt and restart.

Thirteen explicitly fake-worker operator unit methods and eleven recovery
regression methods passed without skips. The early gap-refusal unit assertion
incorrectly required byte identity of SQLite WAL bookkeeping during audit. The
declared audit contract permits bookkeeping changes; the corrected test verifies
that the corrupted durable SQL contents are preserved and no repair occurs.
The first inventory command used the wrong CLI flag and did not run the check;
the corrected required-source inventory passed. Neither is native qualification.

The first actual run at a87a198641d4eeeef7dbd43762c436903668f029 reached
signed payment, then refused normal target restart because the inherited stop
helper had popped its process handle. The CLI correctly retained the unknown
socket. The wrapper now retains the actual terminated test Popen and socket inode,
removing only the same dead test endpoint; its outer source comparison now uses
the same recovery source function. Fresh run02 at the corrected source qualified.
First failed reports/log/artifacts remain outside and in the delivery ZIP.
Review also strengthened raw serving/stopped PID/start-ticks, exact pins and
socket cleanup evidence; the new runtime was rerun on a wholly fresh network.
Seventeen operator and sixteen recovery receipt tamper cases were refused.

Separate native replay verifies both public proofs, both signed state witnesses
and both provider headers. Original P1-P7 and the preceding P8 contracts/runtime
remain byte-identical. The verifier is an explicit single-link copy of the same
pinned Cargo output; its original hard-linked build remains unchanged.

This is finite one-trusted-host synthetic qualification. Doctor does not execute
native code or verify store replay; audit opens SQLite and may update WAL
bookkeeping but cannot repair monetary/history state. The CLI starts no engine,
generates no keys/genesis, chooses no trust, transmits no payment and repairs no
workspace. Signing-state recovery, independent operators, production trust and
freshness, hostile hosts/networks, power-loss durability, production privacy/custody,
pruning/scale, economics, external review and public launch remain unassessed.
Crashed process audit counters remain unavailable; measured totals are retained
receipts, not a claim to count every executed native call.
