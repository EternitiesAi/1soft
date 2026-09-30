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

The manifest-gated final report is retained separately under `evidence/` and
checks exact base/deliverable bytes and pinned dependency versions before/after
execution. Source byte identity establishes preservation, not consensus or security.
The parent owns explorer integration, independent read-only contract review,
real-engine acceptance and any publication decision. Existing native and addon
source files were not changed by this component. No historical-only post-expiry
qualification, trust renewal, wallet reconciliation/retry, deployment, public
network, DNS, Actions, paid compute, production keys or real funds were added.
