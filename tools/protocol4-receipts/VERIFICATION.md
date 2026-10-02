# Receipt component verification

The first focused 32-case local run passed on 30 September 2026 using the pinned
Python environment. It exercised strict canonical parsing, deep/oversized input,
external policy/genesis/deadline checks, transfer-only selection, tampered metadata,
wire/signature/payer/state/history/headers/signer bindings, positive receipt identity
across two validator handovers, and a rejected committed replay that cannot claim
a second execution receipt.

Archive cases exercise exclusive/private initialization and output, reopen and
content-addressed identity, concurrent duplicate insertion, retained count/byte
capacity refusal, transactional failure after INSERT, unknown/empty databases,
wrong pins/expiry, stored payload/index tamper, symlink/hardlink/sidecar rejection,
and durable clock regression. A read-only reopen/get/inspect keeps database bytes
and configuration/clock unchanged.

CLI consumers run in subprocesses with a cleared import environment. They export,
verify and archive/reopen canonical bytes, reject output overwrite and supplied
historical-clock flags, and omit malformed-input secrets from errors. An actual
existing P4 wallet/delivery caller creates a disposable grant transfer, executes
its wire through the native application, imports its receipt without RPC/submission,
and exports full evidence through unchanged `delivery.export_receipt`. The capsule
is then reopened and archived after that test's own wallet/delivery/key directory
has been removed. Wallet status remains unchanged during import/export/capsule
creation, and the fixture records no submissions.

The test fixtures execute the real local native P4 implementation with synthetic
committee signatures. These are not CometBFT votes, independent validator hosts,
public consensus, real funds or a hostile-host custody/security audit. The capsule
verifier deliberately calls both unchanged public verifiers, causing two bounded
full-history replays per verification. This favors an explicit API boundary over
performance; long-history production scaling remains unqualified.

The unchanged historical preintegration report
`evidence/receipt-tests-20260930.json` records the original 32-case run against
parent `4133b3fd632bbbb44eba34447b8aefb67e637f3b`. It checked exact base/deliverable
bytes and pinned dependency versions before/after execution, without the later
integrated-source qualification. This report does not qualify any integration
commit. New current-source reports are written outside the checkout after the
candidate is committed and clean. Source byte identity establishes preservation,
not consensus or security.
The parent owns explorer integration, independent read-only contract review,
real-engine acceptance and any publication decision. Existing native and addon
source files were not changed by this component. No historical-only post-expiry
qualification, trust renewal, wallet reconciliation/retry, deployment, public
network, DNS, Actions, paid compute, production keys or real funds were added.

## Integrated-source qualification repair

The original receipt entrypoint required HEAD to equal the dependency parent
`4133b3fd632bbbb44eba34447b8aefb67e637f3b`. That was a verification-continuation
defect: clean additive integration `dfda2b3df2c661feed3faa3650a7b2048882e261`
was refused even though all pinned native/existing-addon bytes remained unchanged.
The earlier passing component report and engine evidence remain bound to the
source revisions that actually produced them.

The revised prerequisite checks `git merge-base --is-ancestor` for the original
parent against the current source commit, retains all 190 dependency byte pins,
and requires the unchanged release `source_identity` gate at current HEAD both
before and after the receipt suite. That existing gate verifies a clean
tracked/untracked checkout and every tracked byte/mode. The complete identities
must match; the report records original `parent_commit` and current
`source_commit`, `source_tree`, and `source_id` distinctly. The installed tool
must reside in that same selected checkout. No skip flag or dirty-source bypass
was introduced. Reports should be written outside the source checkout.

Four narrow helper tests check an accepted clean descendant, unrelated/missing
ancestry rejection, propagation of dirty/byte-mismatch source-gate rejection,
and refusal when commit/tree/source digest or tracked-file identity changes
across the run. These use controlled mocks to exercise helper behavior and do
not qualify a real checkout. The complete revised candidate must be committed
and rerun through its own clean-source receipt and engine gates; old reports are
not evidence for that new exact commit.
