//! Synthetic deterministic fixtures only. No production proving/key API.
use crate::{
    context::Context,
    proof::Profile,
    relation::{derived, fixture_pair, input_note, Assignment},
    wire::encode,
    F,
};
use ff::PrimeField;
use std::{fs, path::Path};
fn hex(f: F) -> String {
    f.to_repr().iter().map(|b| format!("{b:02x}")).collect()
}
fn refreshed(mut loser: Assignment, winner: &Assignment, context: &Context) -> Assignment {
    loser.public[4] = context.root();
    loser.witness.parent_spent = 6;
    loser.witness.parent_version = 2;
    loser.witness.parent_blind = winner.witness.parent_next_blind;
    loser.witness.payment = 2;
    loser.witness.change_value = 6;
    derived(&mut loser);
    loser
}
pub fn emit(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    let profile = Profile::new()?;
    let (context, a, b) = fixture_pair();
    let mut ab = context.clone();
    ab.parent = a.public[9];
    ab.grants[0].1 = a.public[10];
    let mut ba = context.clone();
    ba.parent = b.public[9];
    ba.grants[1].1 = b.public[10];
    let mut revoked = context.clone();
    revoked.revoke(a.public[6])?;
    let mut survivor = b.clone();
    survivor.public[4] = revoked.root();
    derived(&mut survivor);
    let mut duplicate_request = refreshed(b.clone(), &a, &ab);
    duplicate_request.public[18] = a.public[18];
    derived(&mut duplicate_request);
    let items = [
        ("a", a.clone()),
        ("b", b.clone()),
        ("after_a_b", refreshed(b.clone(), &a, &ab)),
        ("after_b_a", refreshed(a.clone(), &b, &ba)),
        ("revoked_a_b", survivor),
        ("duplicate_request", duplicate_request),
    ];
    for (i, (name, assignment)) in items.into_iter().enumerate() {
        let public = assignment.public;
        let proof = profile.prove(assignment, [i as u8 + 1; 32])?;
        fs::write(path.join(format!("{name}.tx")), encode(&public, &proof)?)?;
    }
    let slots = [context.grants[0], context.grants[1]];
    let manifest=format!("{{\"genesis\":\"{}\",\"asset\":\"{}\",\"mission\":\"{}\",\"parent_id\":\"{}\",\"epoch\":1,\"parent\":\"{}\",\"grants\":[[\"{}\",\"{}\"],[\"{}\",\"{}\"]],\"fee\":2,\"notes\":[\"{}\",\"{}\"]}}\n",
        hex(context.genesis),hex(context.asset),hex(context.mission),hex(context.parent_id),hex(context.parent),
        hex(slots[0].0),hex(slots[0].1),hex(slots[1].0),hex(slots[1].1),hex(input_note(&a)),hex(input_note(&b)));
    fs::write(path.join("genesis.json"), manifest)?;
    let (params, vk) = profile.identities()?;
    println!("TREASURY_FIXTURES {{\"actual_halo2_proofs\":6,\"proof_bytes\":{},\"parameter_sha256\":\"{}\",\"verifying_key_sha256\":\"{}\"}}",crate::PROOF_BYTES,
        params.iter().map(|b|format!("{b:02x}")).collect::<String>(),vk.iter().map(|b|format!("{b:02x}")).collect::<String>());
    Ok(())
}
