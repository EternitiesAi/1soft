use ff::Field;
use private_treasury_payment_lab::{
    proof::Profile,
    relation::{derived, fixture_pair, validate},
    wire::{decode, encode},
    F,
};
#[test]
fn actual_composite_proof_rejects_cross_bindings_and_malformed_envelopes() {
    let profile = Profile::new().unwrap();
    let (_, a, b) = fixture_pair();
    let proof = profile.prove(a.clone(), [21; 32]).unwrap();
    let raw = encode(&a.public, &proof).unwrap();
    let (public, bytes) = decode(&raw).unwrap();
    assert_eq!(public, a.public);
    profile.verify(&public, bytes).unwrap();
    for i in 0..25 {
        let mut changed = a.public;
        changed[i] += F::ONE;
        assert!(profile.verify(&changed, &proof).is_err(), "field {i}");
    }
    assert!(profile.verify(&b.public, &proof).is_err());
    for size in [0, 1, raw.len() - 1, raw.len() + 1] {
        let mut bad = raw.clone();
        bad.resize(size, 0);
        assert!(decode(&bad).is_err());
    }
    let mut bad = raw.clone();
    bad[8..40].fill(255);
    assert!(decode(&bad).is_err());
    let mut bad = raw.clone();
    bad[0] ^= 1;
    assert!(decode(&bad).is_err());
    let mut bad = proof.clone();
    bad[0] ^= 1;
    assert!(profile.verify(&a.public, &bad).is_err());
    for length in [0, 1, proof.len() - 1] {
        assert!(profile.verify(&a.public, &proof[..length]).is_err());
    }
    let mut bad = proof.clone();
    bad.push(0);
    assert!(profile.verify(&a.public, &bad).is_err());
    let mut a = a;
    a.witness.input_value = 9;
    derived(&mut a);
    assert!(validate(&a).is_err());
    assert!(profile.prove(a, [9; 32]).is_err());
    let (params, vk) = profile.identities().unwrap();
    println!("TREASURY_PROFILE {{\"proof_bytes\":{},\"parameter_sha256\":\"{}\",\"verifying_key_sha256\":\"{}\"}}",proof.len(),hex(&params),hex(&vk));
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}
