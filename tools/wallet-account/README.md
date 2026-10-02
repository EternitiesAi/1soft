# 1soft account view

A working read-only account inspector and private HTML/JSON statement, using the
published certificate-wallet and its pending-obligation accounting. This is not
a signer, a second wallet, a public service or a mock browser balance.

The normal path works against exact published PR #7 source
`7635ce053315328dabb78c6b981654c9610e3152`, tree
`6027f766fa97b2a85850e441782f4b76142cedb4`. It does not need the unpublished
catch-up core or the optional refresh/diagnostic clients. On a checkout containing
this add-on and that native source, with the existing dependencies installed:

```sh
python tools/wallet-account/tools/verify.py --native-root .
PYTHONPATH=src python tools/wallet-account/scripts/account.py \
  --genesis /private/genesis.json --policy /private/policy.json \
  --journal /private/wallet.sqlite --account ACCOUNT_ID
```

Use the separately chosen engine genesis and existing CertifiedWallet policy,
not a policy downloaded from an endpoint. The account ID is explicit. Querying an
account in authenticated state does not prove that the caller owns its key.

Add `--format html --output /private/new-report.html` for a self-contained account
statement. Its output directory must be privately owned, and an existing output
is never overwritten. With no output file, JSON goes to the terminal. Report
files contain private account data, but not keys, raw signatures or the complete
wallet snapshot. They are not encrypted or independently signed proofs.

## What the reader establishes

It opens the existing journal with SQLite `mode=ro`, starts one consistent read
transaction, checks the pinned policy, signed full-state witness, native records,
receipt history and exact locally signed obligations. It reports only the chosen
account, its budgets/grants, its decisions and relevant recorded activity.

Recorded balance, pending signed debit including fees, and uncommitted headroom
are separate quantities. A grant's effective next-debit ceiling is the minimum of
account headroom, its individual remainder and its shared-budget remainder.
Inactive grants have a zero effective ceiling; stale evidence or unfinished
header catch-up suppresses this estimate entirely. No ceiling is authorization.

The displayed balance must also equal its genesis allocation plus all recorded
native credits and debits, including fees and sponsored account creation. History
lists can be shortened for display, but accounting uses the complete validated
history. All truncated lists expose their total count. Default limit: 50 entries
per list; maximum: 200. Unsupported/pruned state is refused, not filled with zeros.

Policy expiry, stale/future evidence, local-clock rollback and newer header-only
progress are explicit warnings. Historical inspection remains possible after
policy expiry; it never renews trust or permits signing. A copied HTML/JSON report
can be edited. Re-run the inspector against the trusted journal to verify again.

## No financial effects

No key unlock, signing, broadcast, RPC read, policy renewal, reservation mutation,
schema migration, wallet creation or journal replacement exists in this add-on.
SQLite may maintain ordinary WAL coordination files even for a read-only
connection; no logical wallet table is modified. The reader does not use
`immutable=1`, which would be wrong for a live journal with committed WAL data.

A read transaction sees one SQLite snapshot even when another signer commits.
The next invocation can see that newer signature; this report is not a continuous
session and does not lock future spending. Other devices, other journals, raw
keys and whole-workspace rollback remain outside local reservation guarantees.

The local filesystem and initial trust configuration must be trustworthy. There
are bounds on source bytes, decisions, rows and output, but full-state validation
still costs CPU/RAM and is not production-scale authenticated indexing. No new
cryptography, monetary rule, reserve backing, card integration or identity work.

## Optional catch-up compatibility

Where the separate catch-up implementation is installed, the reader also checks
its saved signed-header frontier. Newer headers do not advance displayed balances
or retire pending signatures. The two optional integration tests use the unchanged
returned core at declared commit `4fbebc8461b80538a85cf14b181f282ff60583f9`, tree
`af1963fe7b16fa0be030ccee47c731795cbfad71`:

```sh
python tools/wallet-account/tools/verify.py --native-root /path/to/that/source --with-catchup
```

No catch-up implementation is copied or republished here. No previously blocked
source is being renamed, encoded, substituted or routed around a restriction.

## Reproduce the four-step specimen

```sh
python tools/wallet-account/tools/demo.py --native-root . --output /private/new-demo
```

The fixture signs Raven's 58+2 and Atlas's 38+2 payments, executes them through
the native application, and projects pending 60/100/40/0 against recorded budget
spending 0/0/60/100. It exports four HTML/JSON statements and one scenario report.
Disposable encrypted fixture keys remain temporary; none is exported. Committee
headers are synthetic, not a new CometBFT run. The specimen is not a live wallet.

See VERIFICATION.md for exact executed scopes and incomplete attempts. Licensing
remains governed by the repository's existing NOTICE; no new license is granted.
