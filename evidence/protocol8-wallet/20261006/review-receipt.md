# P8 wallet review

Two inherited built-in AI peers performed read-only source reviews; root owns
implementation. No paid worker/provider call and no external specialist
cryptographic certification were used.

The authority peer reviewed certified import, monotonic signed observations,
durable holds, original-wire recovery, delivery and conflict behavior. Root added
closed origin-wire/height and completion/index validation and narrowed the wallet
validity policy to an exclusive upper bound of 64. Its initial txid-only concern
was corrected by tracing reconciliation through `_result()` to `_receipt()`,
which verifies exact raw wire, statement, ID and receipt. A genuine distinct
conflicting spend and signed held-conflict resolution are included in the actual
gate. Updated source review found no further concrete blocker.

The first actual run passed all wallet/consensus behavioral checks but its
private-material scan incorrectly included the sender's public destination
H810 key as a secret, which also appears in the recipient's public inventory.
Root restricted primitive classification to actual secret/origin/blind fields
and expanded coverage to the complete private request and every new proving
request's openings. This is a false-positive classification repair, not
acceptance of a private leak. The original failed receipt/log is retained;
qualification requires a new clean-source run on fresh validators.

The native peer reviewed H810/H811/H814/H816 projection, root/path, complete
private request reconstruction, destination public key, exact response bounds,
executable inode pins, child resource limits and process-group cleanup. No
concrete native/controller blocker was found. Private openings are retained
encrypted before proving; pure local construction has no external effect.

A subsequent checker review found the expected validator log name was `node`
instead of the actual `engine` prefix. This is a post-run checker repair and
does not change the executed wallet/proof/network source. Expected helper
refusals return exit 2 and are reaped; genuine proving/fixture processes must
exit 0. Detailed post-run evidence review is recorded separately when complete.

The seven unit methods use fake envelope/controller identity and a malformed
shell worker only for storage/process mechanics. They make no native proof,
consensus, custody or deployment claim. The live gate and separate replay are
the sources for actual local native/certificate evidence.

The native peer independently reviewed the corrected scanner and found coverage
expanded: every complete private proving request, actual secret/origin/blind
slots, recipient secrets, AES keys and delivered private opening primitives are
checked against the public report and raw artifacts. The public H810 key is
properly excluded from credential classification. It found no remaining concrete
blocker in this correction. This scan is not a hostile-host privacy audit.

The authority peer then inspected the completed run02 receipt: all 22 checks in
order, one broadcast/retained attempt, exact original-wire recovery, cold reopen,
state heights 2/4/6 with signed next headers, real held-input conflict, 13 public
artifacts and reaped processes. It found no material evidence gap requiring a
gate change and affirmed the finite trusted-host/AS-OF qualification boundary.

The separate actual native replay returned successfully with four proofs and
three certificates. An additional nine-case integration fault probe used actual
certified receive/native construction with a deliberately malformed prover.
It verified durable unknown-proof holding, cold reopen, refusal of a second
intent without another prover call, and six malformed encrypted-record refusals.
The malformed executable produces no valid proof or network submission.
