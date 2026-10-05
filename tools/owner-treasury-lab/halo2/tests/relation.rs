use ff::{Field, PrimeField};
use halo2_proofs::dev::MockProver;
use owner_treasury_lab::{
    circuit::TreasuryCircuit,
    relation::{derived, fixture, validate},
    F, K,
};
fn satisfied(a: owner_treasury_lab::relation::Assignment) -> bool {
    let p = a.public;
    MockProver::run(K, &TreasuryCircuit::new(a), vec![p.to_vec()])
        .map(|v| v.verify().is_ok())
        .unwrap_or(false)
}
#[test]
fn valid_conserved_payment_with_shared_authority() {
    let a = fixture(2);
    validate(&a).unwrap();
    assert!(satisfied(a));
}
#[test]
fn payment_requires_real_input_and_exact_fee_inclusive_change() {
    for i in 0..3 {
        let mut a = fixture(2);
        match i {
            0 => a.witness.input_value = 9,
            1 => a.witness.change_value = 5,
            _ => a.witness.change_value = 0,
        }
        derived(&mut a);
        assert!(validate(&a).is_err(), "native value case {i}");
        assert!(!satisfied(a), "circuit value case {i}");
    }
}
#[test]
fn change_cannot_escape_the_enrolled_agent() {
    let mut a = fixture(2);
    a.witness.change_key += F::ONE;
    derived(&mut a);
    assert!(validate(&a).is_err());
    assert!(!satisfied(a));
}

#[test]
fn every_public_binding_is_constrained() {
    let original = fixture(2);
    for i in 0..30 {
        let mut a = original.clone();
        a.public[i] += F::ONE;
        assert!(!satisfied(a), "public {i}");
    }
}
#[test]
fn note_membership_nullifier_and_openings_are_constrained() {
    for i in 0..10 {
        let mut a = fixture(2);
        match i {
            0 => a.witness.input_note_secret += F::ONE,
            1 => a.witness.input_blind += F::ONE,
            2 => a.witness.path[0] += F::ONE,
            3 => a.witness.input_position = 1,
            4 => a.witness.payment_note_secret += F::ONE,
            5 => a.witness.change_note_secret += F::ONE,
            6 => a.witness.change_blind += F::ONE,
            7 => a.witness.payment_expiry += 1,
            8 => a.witness.input_expiry += 1,
            _ => a.witness.change_expiry += 1,
        }
        assert!(validate(&a).is_err());
        assert!(!satisfied(a), "opening {i}");
    }
}
#[test]
fn fresh_bindings_do_not_allow_expiry_zero_or_overflow() {
    for i in 0..11 {
        let mut a = fixture(2);
        match i {
            0 => a.witness.input_expiry = 19,
            1 => a.witness.payment_expiry = 19,
            2 => a.witness.input_position = 16,
            3 => a.witness.input_blind = F::ZERO,
            4 => a.witness.payment_note_secret = F::ZERO,
            5 => a.witness.change_note_secret = F::ZERO,
            6 => a.witness.change_expiry = 31,
            7 => a.witness.payment = u64::MAX,
            8 => a.witness.parent_spent = u64::MAX,
            9 => a.witness.parent_version = u64::MAX,
            _ => a.witness.grant_cap = 5,
        }
        derived(&mut a);
        assert!(validate(&a).is_err());
        assert!(!satisfied(a), "fresh {i}");
    }
}
#[test]
fn fee_and_u64_edges_preserve_exact_conservation() {
    let mut a = fixture(2);
    a.witness.parent_cap = u64::MAX;
    a.witness.grant_cap = u64::MAX;
    a.witness.payment = u64::MAX - 3;
    a.witness.input_value = u64::MAX;
    a.witness.change_value = 1;
    derived(&mut a);
    validate(&a).unwrap();
    assert!(satisfied(a.clone()));
    a.witness.change_value = 2;
    derived(&mut a);
    assert!(validate(&a).is_err());
    assert!(!satisfied(a));
    for i in 14..18 {
        let mut a = fixture(2);
        a.public[i] = F::from_u128(1u128 << 64);
        derived(&mut a);
        assert!(validate(&a).is_err());
        assert!(!satisfied(a));
    }
}

#[test]
fn current_old_openings_cannot_authorize_forged_successors() {
    use owner_treasury_lab::relation::{authorization, composite_binding, grant, parent};
    let original = fixture(2);
    for i in 0..4 {
        let mut forged = original.clone();
        match i {
            0 => forged.witness.parent_cap += 1,
            1 => forged.witness.recipient += F::ONE,
            2 => forged.witness.grant_expiry += 1,
            _ => forged.witness.agent_secret += F::ONE,
        }
        let mut a = original.clone();
        a.public[9] = parent(&forged, true);
        a.public[10] = grant(&forged, true);
        a.public[19] = authorization(&a.public);
        a.public[24] = composite_binding(&a.public);
        assert_eq!(parent(&a, false), original.public[7]);
        assert_eq!(grant(&a, false), original.public[8]);
        assert!(validate(&a).is_err());
        assert!(!satisfied(a));
    }
}
#[test]
fn grant_expiry_fences_spend_even_when_value_notes_live_longer() {
    let mut a = fixture(2);
    a.witness.input_expiry = 40;
    a.witness.change_expiry = 40;
    a.witness.payment_expiry = 40;
    derived(&mut a);
    validate(&a).unwrap();
    assert!(satisfied(a.clone()));
    a.public[16] = F::from(31);
    derived(&mut a);
    assert!(validate(&a).is_err());
    assert!(!satisfied(a));
}

#[test]
fn lifecycle_integer_and_key_fields_are_constrained() {
    for i in [25, 26, 28] {
        let mut a = fixture(2);
        a.public[i] = F::from_u128(1u128 << 64);
        derived(&mut a);
        assert!(validate(&a).is_err());
        assert!(!satisfied(a), "metadata range {i}");
    }
    for i in [26, 27, 28, 29] {
        let mut a = fixture(2);
        a.public[i] = F::ZERO;
        derived(&mut a);
        assert!(validate(&a).is_err());
        assert!(!satisfied(a), "metadata zero/key {i}");
    }
}
#[test]
fn old_restricted_note_cannot_be_transplanted_to_new_generation() {
    use owner_treasury_lab::relation::{composite_binding, input_note};
    let original = fixture(2);
    let old_note = input_note(&original);
    let anchor = original.public[20];
    let mut rotated = original.clone();
    rotated.public[26] += F::ONE;
    derived(&mut rotated);
    assert_ne!(old_note, input_note(&rotated));
    rotated.public[20] = anchor;
    rotated.public[24] = composite_binding(&rotated.public);
    assert!(validate(&rotated).is_err());
    assert!(!satisfied(rotated));
}
#[test]
fn owner_sequence_changes_binding_but_does_not_migrate_notes() {
    use owner_treasury_lab::relation::input_note;
    let original = fixture(2);
    let mut fresh = original.clone();
    fresh.public[25] += F::ONE;
    derived(&mut fresh);
    assert_eq!(input_note(&original), input_note(&fresh));
    assert_ne!(original.public[24], fresh.public[24]);
    validate(&fresh).unwrap();
    assert!(satisfied(fresh));
}
#[test]
fn context_fences_exact_owner_and_grant_metadata() {
    use owner_treasury_lab::relation::fixture_pair;
    let (c, a, _) = fixture_pair();
    assert_eq!(c.check(&a.public, 1).unwrap(), 0);
    for i in [25, 26, 27, 28, 29] {
        let mut stale = a.clone();
        stale.public[i] += F::ONE;
        derived(&mut stale);
        assert!(c.check(&stale.public, 1).is_err(), "current metadata {i}");
    }
    let mut changed = c.clone();
    changed.owner_sequence += 1;
    assert_ne!(c.root(), changed.root());
    assert!(changed.check(&a.public, 1).is_err());
    let mut fresh = a.clone();
    fresh.public[25] = F::from(changed.owner_sequence);
    fresh.public[4] = changed.root();
    derived(&mut fresh);
    assert_eq!(changed.check(&fresh.public, 1).unwrap(), 0);
}
#[test]
fn owner_key_uses_exact_two_u128_limbs() {
    use owner_treasury_lab::context::owner_key_commitment;
    use shielded_consensus_halo2::tree::native_hash;
    let key = [255u8; 32];
    let low = u128::from_le_bytes(key[..16].try_into().unwrap());
    let high = u128::from_le_bytes(key[16..].try_into().unwrap());
    assert_eq!(
        owner_key_commitment(key),
        native_hash([F::from(531), F::from_u128(low), F::from_u128(high)])
    );
    let mut other = key;
    other[31] = 254;
    assert_ne!(owner_key_commitment(key), owner_key_commitment(other));
}

#[test]
fn network_domain_preserves_high_limb_and_separates_owner_key() {
    use owner_treasury_lab::context::{network_domain, owner_key_commitment};
    let bytes = [255u8; 32];
    let mut changed = bytes;
    changed[31] = 254;
    assert_ne!(network_domain(bytes), network_domain(changed));
    assert_ne!(network_domain(bytes), owner_key_commitment(bytes));
}
