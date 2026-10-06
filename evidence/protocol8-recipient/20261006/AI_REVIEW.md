# P8 native recipient milestone review

Executed source0e88a2ff6b78b8f290827a116839fe697b733344, tree
3f281ebe096b961aa43e8f6a7079f05c7fbdc7f4. Base/P7 merge
4cc3cefe98681c7c724e190dbe8dc8909dfb9b8a. The selected actual receipt is
recipient-qualified-02.json, SHA256
cd1d1d707b7d83895b4940e4bd0047a9ec682dcb3d70dc4aa21b1b6b32234899.

Seven native relation/request methods and ten Python kernel/schema methods
passed with zero skips. Native unit constraints use MockProver and independent
u128 arithmetic; Python boundary/schema tests use explicitly fake workers and
proofs. They are not presented as actual cryptographic execution. The selected
actual gate separately generated four randomized Halo2 proofs (first transfer,
recipient re-spend, same-statement fresh transcript and valid competing intent),
passed24 checks and reaped53 measured native processes. No native child timed out.
The separately built no-default-features verifier excludes private proving,
request parsing and fixture modules. Cargo resolve reported empty feature sets
for both recipient-transfer and its shared-consensus dependency.

The strict public checker independently recomputed all four native verifications
and the accepted two-receipt history. It then replayed the first payment and
refused the cryptographically valid competing spend with the exact already-
consumed error. This is algorithmic replay, not an external cryptographic audit.
Its15 measured processes were reaped. The final state has5 typed notes,2 consumed
nullifiers/requests and2 fees; the synthetic values are20 ->12+7+1, then12 ->5+6+1.

Two read-only AI peers reviewed the native relation/request/wire and state/receipt
authority boundaries. They found no remaining concrete mismatch in the reviewed
source. A peer initially read stale Worker.call code and reported missing process
fields; after reading the exact live path, it withdrew that finding. The current
worker records PID/start ticks, resource limits, timeout and reaping for every
native invocation. These peer reviews are not specialist security certification.

Earlier source-preparation attempts had a missing Rust PrimeField import and
quoted-string escaping errors, including the checker backslash literal. They
were repaired before the selected clean-source gate. Their raw output is in
session history, not an exported log file; do not infer an archived raw failure
receipt. Earlier actual run01 passed23 checks at7eac39ea6982e484d94ea6ea19c84594d7cdd835;
run02 strengthens that version with a valid competing proof and becomes the
selected milestone. Neither prior probes nor run01 qualify changed run02 source.

P1–P7 runtime/profile/history bytes remain unchanged. Only previous README,
ROADMAP and source inventory were edited; P8 implementation is additive.
Runtime hashes from the selected run remained unchanged during this evidence
registration. No CometBFT/ABCI/certificate/custody caller was exercised for P8.
Genesis and height are externally trusted local fixture inputs, not authenticated
network evidence. No migration, human identity, hostile-host privacy, production
privacy/custody/security, public release or real-funds claim is established.
No Actions, paid/public compute, deployment/DNS/site, other projects or force
pushes were used. Next qualify versioned authenticated P8 state/ABCI integration,
then recipient custody and fresh four-validator receive/re-spend/recovery gates.
