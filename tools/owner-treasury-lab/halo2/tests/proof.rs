use ff::{Field, PrimeField};
use owner_treasury_lab::{
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
    for i in 0..30 {
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
    println!("OWNER_TREASURY_PROFILE {{\"proof_bytes\":{},\"parameter_sha256\":\"{}\",\"verifying_key_sha256\":\"{}\"}}",proof.len(),hex(&params),hex(&vk));
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|v| format!("{v:02x}")).collect()
}

#[test]
fn mathematically_valid_fabricated_context_is_refused_by_native_caller() {
    let profile = Profile::new().unwrap();
    let (c, a, _) = fixture_pair();
    let mut forged = a.clone();
    forged.public[4] += F::ONE;
    forged.public[25] += F::ONE;
    forged.public[27] += F::ONE;
    derived(&mut forged);
    validate(&forged).unwrap();
    let proof = profile.prove(forged.clone(), [41; 32]).unwrap();
    profile.verify(&forged.public, &proof).unwrap();
    assert!(c.check(&forged.public, 1).is_err());
    let mut wrong_epoch = a;
    wrong_epoch.public[28] += F::ONE;
    derived(&mut wrong_epoch);
    validate(&wrong_epoch).unwrap();
    assert!(c.check(&wrong_epoch.public, 1).is_err());
}
#[test]
fn wire_refuses_old_profile_and_out_of_range_lifecycle_metadata() {
    let old=include_bytes!("../../../../evidence/protocol6-treasury/20261004/engine-qualified-01.json.artifacts/fixture-a.tx");
    assert!(decode(old).is_err());
    let (_, a, _) = fixture_pair();
    for i in [25, 26, 28] {
        let mut p = a.public;
        p[i] = F::from_u128(1u128 << 64);
        let raw = encode(&p, &vec![0; owner_treasury_lab::PROOF_BYTES]).unwrap();
        assert!(decode(&raw).is_err());
    }
}
