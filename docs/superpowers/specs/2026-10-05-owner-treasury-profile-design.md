# Authenticated owner treasury successor profile

## Target and authority

Build a fresh development proof/profile and consensus caller for owner-signed
enrollment, revocation and rotation of two fixed agent spending grants. Preserve
every P1-P6 runtime/proof byte and historical receipt. No paid/public compute,
deployment/DNS/site, Actions, other projects, real funds or production keys.
Root implements; AI colleagues review bounded source/acceptance independently.

## New relation

`tools/owner-treasury-lab` is an isolated successor laboratory first. It must not
claim consensus authority until a fresh versioned application and actual engine
receipts exist. A P6 wrapper is insufficient. New30-field payment statement
preserves positions0..24 structurally, changes relation version to2 and domains,
and adds25 owner_sequence,26 grant_generation,27 owner_key_commitment,28 owner_epoch,
29 selected_agent_key_commitment. Sequence/generation/epoch are canonical u64;
generation/epoch/key commitments are nonzero, initial sequence can be0.

Ed25519 owner public key stays exact32-byte state/signed-command data. Its field
commitment uses Poseidon domain531 plus two exact little-endian128-bit limbs;
never reduce the entire key modulo Pasta or interpret it as a field element.
New context root commits genesis/asset/mission/parent-id/epoch, owner_epoch,
sequence/key commitment, parent, fee and both stable IDs/generations/active
commitments/agent-key commitments. Native current-state checks compare every
selected metadata field before accepting a real proof. The circuit binds the
new metadata in authorization and composite hashes, selected agent secret/key,
grant commitment and restricted note membership/change generation.

Owner sequence advances only accepted commands. Grant generation advances only
enrollment from0 to1 or rotation old+1; payments increment private grant spend
version and preserve generation. Revocation retains the last generation and
marks the slot inactive. Stable grant IDs never recycle. Enrollment only once
at generation0; rotation can reactivate a revoked slot with new generation.
Restricted notes bind generation and owner_epoch, not owner_sequence. Unrelated
grant commands stale prepared proof context, but do not silently destroy/relabel
the unrelated grant's notes. Old-generation notes remain quarantined; no migration
or automatic retry/re-signing/replacement. Merchant redemption is a separate gate.

## Signed owner commands and execution

Closed canonical signed command includes fresh profile/genesis/chain identities,
owner key/epoch, next exact sequence, current context root, kind, stable slot ID,
expected generation/old commitment, exact effective height and new commitment/key
where applicable. Ed25519 verification is native consensus authorization, not
an in-circuit signature claim. Wrong domain/key/signature, altered/noncanonical
bytes, duplicates, stale sequence/root/generation/old commitment/height refuse
without partial state change. Overflow/capacity cannot silently wrap.

Payments and commands execute in block order. Payment first may succeed then
the command must reference the new context; revoke first rejects an old payment.
Two commands prepared against one state compete by sequence/context; exactly one
can change that state. Parent, nullifier, note, fee, receipt and AppHash changes
remain atomic and independently replayable. Owner private keys are fixtures only
and must never be included in receipts. Single owner key first; threshold,
owner-key recovery/rotation, funding/minting and production economics are separate.

## Gates

Require native and MockProver relation attacks, actual proofs/corrupt proofs,
new profile/VK/wire pins (universal deterministic public params may legitimately
match the prior K14 setup), real Ed25519 command attacks and both ordered
payment/command races. Then fresh consensus storage replay/crash/reopen audit,
four actual validators, signed-state recovery and conservative wallet holds.
No old proof/profile/worker identity can qualify as the new one. Actual sources,
logs, fixtures and explicit skips/failures are retained. Freeze profile after
discovering real circuit identities, not before pretending old VKs still apply.
