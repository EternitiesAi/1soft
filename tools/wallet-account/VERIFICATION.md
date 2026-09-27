# Account view verification — 2026-09-27

## Exact source basis

The current GitHub read confirmed PR #9 head `b3c5bdc797cf945a922fefb5e9ac1266875314e1`
and PR #8 `610b443afed7e73b5938ac7b8873c6a728e7f6c4`. This new client is independent
of those optional clients and instead targets the fully published PR #7 core.
Main and those existing branches were not modified.

The previously supplied catch-up return archive SHA-256 was rechecked as
`f6da96c5550480c537ef87b24090f56a71971c4a0dc413a6a285c39a4ab464b0`.
Its 106 required files matched. Reversing its supplied patch reconstructed exact
PR #7 tree `6027f766fa97b2a85850e441782f4b76142cedb4`; all 104 PR #7 required
files matched. This reconstruction, not a guessed latest local checkout, is the
normal test dependency. The latest Windows-only Codex return remains uninspected.

## Executed tests

- 45 new account-view tests passed against exact reconstructed PR #7 source.
- 47 new tests passed against the unchanged catch-up core: the same 45 plus two
  optional header-progress tests. Do not add 45 and 47 as distinct cases.
- 114 inherited tests passed separately on exact PR #7: 47 certificate-wallet,
  49 pending-obligation, and 18 budget integration cases.
- 30 separate JavaScript reference tests passed. That reference is not newly
  integrated with the wallet or native accounting.
- The four-step demonstration produced pending 60, 100, 40, 0 and recorded budget
  spending 0, 0, 60, 100, with final account balance 892 after fees. It executes
  actual native transactions with encrypted fixture signing and synthetic headers.
- Desktop 1440px and mobile 390px in-memory rendering checks passed, including no
  outer-page overflow, expected amounts, no script elements or remote requests.

The new tests cover exact policy/witness binding, full receipt balance
reconciliation, fees, pending signatures, concurrent signing while a read snapshot
is open, committed WAL, account-specific filtering, sponsored incoming credit,
consent-only records, grant/parent revocation, key-epoch fencing, expiry absence,
insufficient headroom, disclosed truncation, corrupt evidence and signatures,
missing or wrong wallet files, private paths, no key or socket access, JSON/HTML
CLI behavior and output overwrite refusal. One parameterized test covers P1, P2,
P3 flat state and P3 SMT; those four variants are not four extra test methods.

## Initial failures and incomplete attempts

The initial run against the published core contained two tests that mistakenly
called the unpublished catch-up API and a table-removal test that assumed that
optional table existed. They were separated into an explicitly optional suite;
the published-core test now uses DROP TABLE IF EXISTS. A missing newline in that
new optional test file caused an import failure, corrected before the final run.
Neither issue was a monetary-rule defect, and the failing logs are retained.

A full untouched PR #7 suite was attempted but the tool invocation timed out.
Its partial log is retained and is not counted as a complete suite pass. The
114 individually completed inherited tests are the only claimed inherited
regression scope. No new 971/1,062-case complete suite pass is claimed.

Actual browser file navigation was blocked by the environment. No alternative
navigation was attempted; authored HTML was rendered in memory instead. These
checks establish layout and static content, not deployed navigation, HTTPS or a
public account application. No new real validator execution occurred.

## Effects and limitations

No native source, signing code, reserve calculation, committed ledger state,
existing wallet schema, engine runner, diagnostic client, deployed site, DNS,
Resident/Luna/Psyche lane or production credential was changed. No Actions, paid
compute, public deployment, real funds, force push or merge was used.

A read-only SQLite connection can still use WAL coordination files. Tests assert
unchanged logical wallet state, not an unchanged byte-for-byte shared-memory
file. Source tables, state evidence and pending inventory are read within one
transaction. The report is an editable private projection, not a transportable
signature proof, ownership verification or authorization to spend.

The primitive/documentation basis was checked in official SQLite documentation:
https://www.sqlite.org/uri.html (mode=ro)
https://www.sqlite.org/wal.html (WAL files and read-only constraints)
https://www.sqlite.org/isolation.html (read-transaction snapshot isolation)

Publication and fresh-extraction hashes, exact source identities, and rerun
results are recorded in the companion release-check JSON after packaging. Hash
inventories establish byte identity, not an independent audit or issuer trust.
