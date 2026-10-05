//! Deterministic synthetic proving only; no production keys/prover/custody API.
use crate::{
    context::Context,
    proof::Profile,
    relation::{agent_key, derived, fixture_pair_domain, input_note, tree, Assignment},
    wire::encode,
    F,
};
use ff::{Field, PrimeField};
use std::{fs, path::Path};
fn hex(f: F) -> String {
    f.to_repr().iter().map(|b| format!("{b:02x}")).collect()
}
fn refreshed(mut loser: Assignment, winner: &Assignment, context: &Context) -> Assignment {
    loser.public[4] = context.root();
    loser.public[25] = F::from(context.owner_sequence);
    loser.witness.parent_spent = 6;
    loser.witness.parent_version = 2;
    loser.witness.parent_blind = winner.witness.parent_next_blind;
    loser.witness.payment = 2;
    loser.witness.change_value = 6;
    derived(&mut loser);
    loser
}
fn document(c: &Context, notes: &[F]) -> String {
    let slots = c
        .grants
        .map(|(id, generation, commit, key)| {
            format!(
                "{{\"id\":\"{}\",\"generation\":{},\"commitment\":\"{}\",\"agent_key\":\"{}\"}}",
                hex(id),
                generation,
                hex(commit),
                hex(key)
            )
        })
        .join(",");
    let notes = notes
        .iter()
        .map(|v| format!("\"{}\"", hex(*v)))
        .collect::<Vec<_>>()
        .join(",");
    let owner = c
        .owner_key
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    format!("{{\"genesis\":\"{}\",\"asset\":\"{}\",\"mission\":\"{}\",\"parent_id\":\"{}\",\"epoch\":{},\"owner_key\":\"{}\",\"owner_epoch\":{},\"owner_sequence\":{},\"parent\":\"{}\",\"grants\":[{}],\"fee\":{},\"notes\":[{}]}}\n",hex(c.genesis),hex(c.asset),hex(c.mission),hex(c.parent_id),c.epoch,owner,c.owner_epoch,c.owner_sequence,hex(c.parent),slots,c.fee,notes)
}
pub fn emit(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    emit_domain(path, F::from(11))
}
pub fn emit_domain(path: &Path, genesis: F) -> Result<(), Box<dyn std::error::Error>> {
    if genesis == F::ZERO {
        return Err("zero-fixture-domain".into());
    }
    fs::create_dir(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let profile = Profile::new()?;
    let (mut context, mut a, mut b) = fixture_pair_domain(genesis);
    if genesis != F::from(11) {
        // Bounded synthetic P7 execution window. No production policy claim.
        for item in [&mut a, &mut b] {
            item.public[16] = F::from(60);
            item.witness.grant_expiry = 64;
            item.witness.input_expiry = 64;
            item.witness.change_expiry = 64;
            item.witness.payment_expiry = 64;
            derived(item);
        }
        context.parent = a.public[7];
        context.grants[0].2 = a.public[8];
        context.grants[1].2 = b.public[8];
        a.public[4] = context.root();
        b.public[4] = context.root();
        derived(&mut a);
        derived(&mut b);
    }
    let mut rotated = a.clone();
    rotated.public[25] = F::ONE;
    rotated.public[26] = F::from(2);
    rotated.witness.agent_secret += F::from(100);
    rotated.witness.change_key = agent_key(rotated.witness.agent_secret);
    rotated.public[29] = agent_key(rotated.witness.agent_secret);
    rotated.witness.grant_blind += F::from(100);
    rotated.witness.grant_next_blind += F::from(100);
    rotated.witness.input_note_secret += F::from(100);
    rotated.witness.input_blind += F::from(100);
    rotated.witness.change_note_secret += F::from(100);
    rotated.witness.change_blind += F::from(100);
    rotated.witness.payment_note_secret += F::from(100);
    derived(&mut rotated);
    // Third note is explicitly synthetic pre-seeded generation2 value, not minted by rotation.
    let notes = [input_note(&a), input_note(&b), input_note(&rotated)];
    let (_, paths) = tree(&notes)?;
    for (i, item) in [&mut a, &mut b, &mut rotated].into_iter().enumerate() {
        item.witness.path = paths[i];
        item.witness.input_position = i as u16;
        derived(item);
    }
    let mut rotation = context.clone();
    rotation.owner_sequence = 1;
    rotation.grants[0] = (a.public[6], 2, rotated.public[8], rotated.public[29]);
    rotated.public[4] = rotation.root();
    derived(&mut rotated);
    let mut revoked = context.clone();
    revoked.owner_sequence = 1;
    revoked.grants[0].2 = F::ZERO;
    let mut survivor = b.clone();
    survivor.public[25] = F::ONE;
    survivor.public[4] = revoked.root();
    derived(&mut survivor);
    let mut inactive = context.clone();
    inactive.grants[1] = (b.public[6], 0, F::ZERO, F::ZERO);
    let mut pre_enroll = a.clone();
    pre_enroll.public[4] = inactive.root();
    derived(&mut pre_enroll);
    let mut enrolled = context.clone();
    enrolled.owner_sequence = 1;
    let mut after_enroll = b.clone();
    after_enroll.public[25] = F::ONE;
    after_enroll.public[4] = enrolled.root();
    derived(&mut after_enroll);
    let mut ab = context.clone();
    ab.parent = a.public[9];
    ab.grants[0].2 = a.public[10];
    let mut ba = context.clone();
    ba.parent = b.public[9];
    ba.grants[1].2 = b.public[10];
    let mut duplicate = refreshed(b.clone(), &a, &ab);
    duplicate.public[18] = a.public[18];
    derived(&mut duplicate);
    let mut after_a_revoked = ab.clone();
    after_a_revoked.owner_sequence = 1;
    after_a_revoked.grants[0].2 = F::ZERO;
    let mut reactivation = rotation.clone();
    reactivation.owner_sequence = 2;
    let mut reactivated = rotated.clone();
    reactivated.public[25] = F::from(2);
    reactivated.public[4] = reactivation.root();
    derived(&mut reactivated);
    let mut rotated_paid_revoked = rotation.clone();
    rotated_paid_revoked.owner_sequence = 2;
    rotated_paid_revoked.parent = rotated.public[9];
    rotated_paid_revoked.grants[0].2 = F::ZERO;
    let after_rotated_revoke = refreshed(b.clone(), &rotated, &rotated_paid_revoked);
    let items = [
        ("a", a.clone()),
        ("b", b.clone()),
        ("rotated_a", rotated),
        ("reactivated_a", reactivated),
        ("after_rotated_a_revoke_b", after_rotated_revoke),
        ("revoked_a_b", survivor),
        ("pre_enroll_a", pre_enroll),
        ("after_enroll_b", after_enroll),
        ("after_a_b", refreshed(b.clone(), &a, &ab)),
        ("after_b_a", refreshed(a.clone(), &b, &ba)),
        ("duplicate_request", duplicate),
        ("after_a_revoke_b", refreshed(b, &a, &after_a_revoked)),
    ];
    for (i, (name, assignment)) in items.into_iter().enumerate() {
        let public = assignment.public;
        let proof = profile.prove(assignment, [i as u8 + 71; 32])?;
        fs::write(path.join(format!("{name}.tx")), encode(&public, &proof)?)?;
    }
    fs::write(path.join("genesis.json"), document(&context, &notes))?;
    fs::write(
        path.join("enroll-genesis.json"),
        document(&inactive, &notes),
    )?;
    let (params, vk) = profile.identities()?;
    let h = |b: [u8; 32]| b.iter().map(|v| format!("{v:02x}")).collect::<String>();
    println!("OWNER_TREASURY_FIXTURES {{\"actual_proofs\":12,\"proof_bytes\":{},\"parameter_sha256\":\"{}\",\"verifying_key_sha256\":\"{}\"}}",crate::PROOF_BYTES,h(params),h(vk));
    Ok(())
}
