//! Synthetic test input only. Not a wallet or a deployed opening/discovery API.
use ff::Field;
use owner_treasury_lab::{
    context::network_domain,
    prover_request,
    relation::{agent_key, derived, fixture_pair_domain, input_note, tree, Assignment},
    F,
};
use std::io::{self, Read, Write};

pub fn assignment(bootstrap: [u8; 32]) -> Assignment {
    let (mut context, mut a, mut b) = fixture_pair_domain(network_domain(bootstrap));
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
    let (_, paths) = tree(&[input_note(&a), input_note(&b), input_note(&rotated)]).unwrap();
    a.witness.path = paths[0];
    a.public[4] = context.root();
    // Deliberately differs from all twelve fixed payment fixtures.
    a.witness.payment = 3;
    a.witness.change_value = 5;
    a.witness.parent_next_blind += F::from(700);
    a.witness.grant_next_blind += F::from(701);
    a.public[18] += F::from(1000);
    derived(&mut a);
    a
}
fn main() {
    let mut raw = Vec::new();
    io::stdin().take(33).read_to_end(&mut raw).unwrap();
    let bootstrap: [u8; 32] = raw.try_into().expect("synthetic 32byte bootstrap");
    let request = prover_request::encode(&assignment(bootstrap), bootstrap).unwrap();
    io::stdout().write_all(&request).unwrap();
}
