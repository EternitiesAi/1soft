# Durable private alpha

Dom approved implementation and subagent use on 2026-10-03. This profile is a finite local development product, with authenticated retained history and one shared monetary journal. It does not qualify production consensus, economics, custody, independent operators or on-chain privacy.

## Authority and compatibility

A newly created protocol-4 genesis may explicitly select `development_profile: durable-private-alpha-v1`. Only this literal grants a 4096-block application/replay ceiling. Existing genesis bytes, v1 policy/workspaces, P1/P2/P3, smt-v1, wire signing and ledger rules remain compatible. No existing workspace is migrated. The new read policy uses schema2/format `1soft/protocol4-read-policy/v2`, immutable original genesis/anchor, one-hour sequential trust, and an absolute deadline of original anchor time plus24 hours. Admissions and precommit checks must precede both the prior accepted signed-tip expiry and that fixed deadline. New checkpoints must be recent within300 seconds and original five-second drift. Restart or an expired offline gap cannot renew authority.

## Evidence and resources

New incremental evidence/store/RPC modules retain every canonical signed header, full BlockID, exact transaction list and replay result once. A bounded collection selects its target once and imports at most64 new blocks, including the body of the previous authenticated H+1 lookahead. All signature slots, strict quorum, whole parent IDs, increasing signed time, DataHash, composite AppHash, monetary and registry transitions remain checked. Cold open authenticates the full retained prefix by streaming from original genesis. A process-local cursor can serve deltas only while its file/catalog/transaction identity remains stable. Failed import discards the cursor. Serialized verification flags and unchecked imported ledger state are forbidden.

Small immutable checkpoint references name that shared history and immutable policy. Readers receive explicitly labelled authenticated monetary contexts, never a fabricated full legacy proof. Logical/physical/item quotas are finite and fail closed before writes; history is not pruned or evicted. Legacy proof and read-store formats retain existing bounds and refuse the new genesis in their full-proof verifier.

## Financial continuity

A new wallet journal format stores references to authenticated historical contexts and retains every original review, signed wire, fee-inclusive reservation, nonce, role, budget and decision digest. Approval repeats current trust/freshness and exact review checks before key access and before durable commit. Original signing contexts and reservations are independently reconstructed on cold audit. Signing still has one shared journal; unsigned prepares have no monetary effect. A new delivery format commits one attempt before network I/O, preserves uncertain outcomes without resend, and recognizes only exact successful inclusion as a positive receipt. Missing, stale or expired history cannot release holds. Explicit encrypted historical export remains inert and cannot establish current signing authority or device fencing.

## Qualification and boundaries

Meaningful tests compare incremental replay with existing full-history execution within the legacy domain, detect prefix tampering, wrong rosters/parent/data/state/signatures, stale CAS, rollback, exact expiry/clock regression and capacity/crash failures. Existing v1 expiry and important compatibility suites rerun on changed source. The real pinned CometBFT engine must operate one unchanged genesis/home/database beyond64 and512 and for more than one actual hour, with original payments/attempts/receipts retained through shutdown/reopen and a successful signed payment after the original one-hour boundary. Synthetic time and fixtures are separate evidence.

No paid/PAYG/cloud/public compute, installs, Actions, public exposure/deployment, DNS/site changes, other-project work, real funds/production keys, forcepush, outgoing chats, automations or memory writes. Preserve prior sealed releases, failed runs and the dirty Windows checkout. Independent review, exact candidate qualification, private supported GitHub publication/merge and a source plus sanitized raw evidence ZIP finish this milestone.
