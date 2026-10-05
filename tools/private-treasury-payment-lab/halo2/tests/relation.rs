use ff::{Field, PrimeField};
use halo2_proofs::dev::MockProver;
use private_treasury_payment_lab::{
    circuit::TreasuryCircuit,
    relation::{derived, fixture, validate},
    F, K,
};
fn satisfied(a: private_treasury_payment_lab::relation::Assignment) -> bool {
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
    for i in 0..25 {
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
    use private_treasury_payment_lab::relation::{authorization, composite_binding, grant, parent};
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
