use ff::Field;
use private_authority_proof_lab::{
    context::Context,
    proof::Profile,
    relation::{derived, fixture, validate},
    F,
};

#[test]
fn actual_proofs_bind_shared_current_state_and_ordered_revocation() {
    let profile = Profile::new().unwrap();
    let mut a = fixture(2);
    let mut b = fixture(3);
    let initial = Context {
        genesis: a.public[1],
        asset: a.public[2],
        mission: a.public[3],
        parent_id: a.public[5],
        epoch: 1,
        parent: a.public[7],
        grants: [(a.public[6], a.public[8]), (b.public[6], b.public[8])],
        fee: 2,
    };
    a.public[4] = initial.root();
    derived(&mut a);
    b.public[4] = initial.root();
    derived(&mut b);
    let pa = profile.prove(a.clone(), [1; 32]).unwrap();
    let pb = profile.prove(b.clone(), [2; 32]).unwrap();
    profile.verify(&a.public, &pa).unwrap();
    profile.verify(&b.public, &pb).unwrap();
    let mut changed = a.public;
    changed[4] += F::ONE;
    assert!(profile.verify(&changed, &pa).is_err());
    let mut corrupt = pa.clone();
    corrupt[0] ^= 1;
    assert!(profile.verify(&a.public, &corrupt).is_err());
    for length in [0, 1, pa.len() - 1, pa.len() / 2] {
        assert!(profile.verify(&a.public, &pa[..length]).is_err());
    }
    let mut appended = pa.clone();
    appended.push(0);
    assert!(profile.verify(&a.public, &appended).is_err());
    assert!(profile.verify(&a.public, &vec![0; 65537]).is_err());
    for i in 0..10 {
        let mut wrong = initial.clone();
        match i {
            0 => wrong.genesis += F::ONE,
            1 => wrong.asset += F::ONE,
            2 => wrong.mission += F::ONE,
            3 => wrong.parent_id += F::ONE,
            4 => wrong.epoch += 1,
            5 => wrong.fee += 1,
            6 => wrong.grants[0].0 += F::from(5),
            7 => wrong.grants[0].1 += F::ONE,
            8 => wrong.parent += F::ONE,
            _ => wrong.grants[1].0 = wrong.grants[0].0,
        }
        let before = wrong.root();
        assert!(wrong.commit(&profile, &a.public, &pa, 2).is_err());
        assert_eq!(before, wrong.root());
    }
    for height in [0, 20, 21, u64::MAX] {
        let mut state = initial.clone();
        let before = state.root();
        assert!(state.commit(&profile, &a.public, &pa, height).is_err());
        assert_eq!(before, state.root());
    }
    for height in [1, 19] {
        let mut state = initial.clone();
        state.commit(&profile, &a.public, &pa, height).unwrap();
    }
    for reverse in [false, true] {
        let mut state = initial.clone();
        let (first, fp, second, sp) = if reverse {
            (&b, &pb, &a, &pa)
        } else {
            (&a, &pa, &b, &pb)
        };
        state.commit(&profile, &first.public, fp, 2).unwrap();
        let after = state.clone();
        assert!(state.commit(&profile, &first.public, fp, 2).is_err());
        assert!(state.commit(&profile, &second.public, sp, 2).is_err());
        assert_eq!(state.root(), after.root());
        assert_eq!(state.parent, first.public[9]);
        let mut refreshed = second.clone();
        refreshed.public[4] = state.root();
        refreshed.witness.parent_spent = 6;
        refreshed.witness.parent_version = 2;
        refreshed.witness.parent_blind = first.witness.parent_next_blind;
        refreshed.witness.payment = 2;
        derived(&mut refreshed);
        let next = profile
            .prove(refreshed.clone(), [if reverse { 4 } else { 3 }; 32])
            .unwrap();
        state.commit(&profile, &refreshed.public, &next, 2).unwrap();
        let mut exhausted = refreshed.clone();
        exhausted.public[4] = state.root();
        exhausted.witness.parent_spent = 10;
        exhausted.witness.parent_version = 3;
        exhausted.witness.parent_blind = refreshed.witness.parent_next_blind;
        exhausted.witness.grant_spent = 4;
        exhausted.witness.grant_version = 2;
        exhausted.witness.grant_blind = refreshed.witness.grant_next_blind;
        exhausted.witness.payment = 1;
        derived(&mut exhausted);
        assert!(validate(&exhausted).is_err());
        assert!(profile.prove(exhausted, [8; 32]).is_err());
    }
    let mut revoked = initial.clone();
    revoked.revoke(a.public[6]).unwrap();
    assert!(revoked.commit(&profile, &a.public, &pa, 2).is_err());
    let after = revoked.root();
    assert!(revoked.commit(&profile, &a.public, &pa, 2).is_err());
    assert_eq!(revoked.root(), after);
    b.public[4] = revoked.root();
    derived(&mut b);
    let refreshed = profile.prove(b.clone(), [5; 32]).unwrap();
    revoked.commit(&profile, &b.public, &refreshed, 2).unwrap();
    let (parameters, vk) = profile.identities().unwrap();
    let hex = |bytes: [u8; 32]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    println!("AUTHORITY_EVIDENCE {{\"actual_halo2_proofs\":5,\"proof_bytes\":{},\"same_parent_orders\":2,\"stale_rejected\":true,\"revoked_rejected\":true,\"refreshed_survivor_accepted\":true,\"exact_parent_exhaustion\":true,\"parameter_sha256\":\"{}\",\"verifying_key_sha256\":\"{}\"}}",pa.len(),hex(parameters),hex(vk));
}
