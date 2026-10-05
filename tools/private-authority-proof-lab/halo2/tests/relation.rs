use ff::{Field, PrimeField};
use halo2_proofs::dev::MockProver;
use private_authority_proof_lab::{
    circuit::AuthorityCircuit,
    relation::{authorization, derived, fixture, grant, parent, validate},
    F, K,
};

fn satisfied(a: private_authority_proof_lab::relation::Assignment) -> bool {
    let public = a.public;
    MockProver::run(K, &AuthorityCircuit::new(a), vec![public.to_vec()])
        .map(|p| p.verify().is_ok())
        .unwrap_or(false)
}
#[test]
fn valid_fee_inclusive_shared_authority() {
    let a = fixture(2);
    validate(&a).unwrap();
    assert!(satisfied(a));
}
#[test]
fn each_public_binding_is_constrained() {
    let a = fixture(2);
    // Current-root is externally selected by Context, not a private membership proof.
    // Domain/identity fields can define other valid assignments only if all commitments change.
    for i in 0..20 {
        let mut m = a.clone();
        m.public[i] += F::ONE;
        assert!(!satisfied(m), "public field {i}");
    }
}
#[test]
fn altered_openings_fail_without_replacing_current_commitments() {
    let a = fixture(2);
    for i in 0..15 {
        let mut m = a.clone();
        match i {
            0 => m.witness.parent_cap += 1,
            1 => m.witness.parent_spent += 1,
            2 => m.witness.parent_version += 1,
            3 => m.witness.parent_blind += F::ONE,
            4 => m.witness.parent_next_blind += F::ONE,
            5 => m.witness.grant_cap += 1,
            6 => m.witness.grant_spent += 1,
            7 => m.witness.grant_version += 1,
            8 => m.witness.grant_blind += F::ONE,
            9 => m.witness.grant_next_blind += F::ONE,
            10 => m.witness.grant_expiry += 1,
            11 => m.witness.agent_secret += F::ONE,
            12 => m.witness.recipient += F::ONE,
            13 => m.witness.payment += 1,
            _ => m.witness.payment_blind += F::ONE,
        }
        assert!(validate(&m).is_err());
        assert!(!satisfied(m), "witness field {i}");
    }
}
#[test]
fn fresh_bindings_cannot_hide_overflow_or_cap_exhaustion() {
    for i in 0..7 {
        let mut a = fixture(2);
        match i {
            0 => a.witness.parent_cap = 5,
            1 => a.witness.grant_cap = 5,
            2 => a.witness.parent_spent = u64::MAX,
            3 => a.witness.grant_spent = u64::MAX,
            4 => a.witness.parent_version = u64::MAX,
            5 => a.witness.grant_version = u64::MAX,
            _ => a.witness.payment = u64::MAX,
        }
        derived(&mut a);
        assert!(validate(&a).is_err());
        assert!(!satisfied(a), "range/cap case {i}");
    }
}
#[test]
fn expiry_and_zero_secret_are_circuit_rules() {
    for i in 0..3 {
        let mut a = fixture(2);
        match i {
            0 => a.witness.grant_expiry = 19,
            1 => a.witness.agent_secret = F::ZERO,
            _ => a.witness.payment = 0,
        };
        derived(&mut a);
        assert!(validate(&a).is_err());
        assert!(!satisfied(a));
    }
}

#[test]
fn forged_successors_cannot_change_caps_or_immutable_policy() {
    let original = fixture(2);
    for i in 0..11 {
        let mut forged = original.clone();
        match i {
            0 => forged.witness.parent_cap += 1,
            1 => forged.witness.grant_cap += 1,
            2 => forged.witness.recipient += F::ONE,
            3 => forged.witness.grant_expiry += 1,
            4 => forged.witness.agent_secret += F::ONE,
            5 => forged.public[14] += F::ONE,
            6 => forged.public[3] += F::ONE,
            7 => forged.public[5] += F::ONE,
            8 => forged.public[6] += F::ONE,
            9 => forged.witness.parent_spent = 0,
            _ => forged.witness.grant_version = 0,
        }
        let mut statement = original.clone();
        statement.public[9] = parent(&forged, true);
        statement.public[10] = grant(&forged, true);
        // Case 9 deliberately substitutes an old spent counter for a debit.
        if i == 9 {
            statement.public[9] = parent(&original, false);
        }
        statement.public[19] = authorization(&statement.public);
        // The old opening is still valid: only the claimed successor is forged.
        assert_eq!(parent(&statement, false), original.public[7]);
        assert_eq!(grant(&statement, false), original.public[8]);
        assert!(validate(&statement).is_err(), "successor case {i}");
        assert!(!satisfied(statement), "successor case {i}");
    }
}

#[test]
fn exact_u64_and_cap_edges_match_native_and_circuit() {
    for (payment, fee, spent, cap, valid) in [
        (u64::MAX - 2, 2, 0, u64::MAX, true),
        (u64::MAX - 1, 2, 0, u64::MAX, false),
        (4, 2, 4, 10, true),
        (4, 2, 5, 10, false),
        (1, u64::MAX, 0, u64::MAX, false),
    ] {
        let mut a = fixture(2);
        a.witness.payment = payment;
        a.public[17] = F::from(fee);
        a.witness.parent_spent = spent;
        a.witness.grant_spent = spent;
        a.witness.parent_cap = cap;
        a.witness.grant_cap = cap;
        derived(&mut a);
        assert_eq!(validate(&a).is_ok(), valid);
        assert_eq!(satisfied(a), valid);
    }
    for i in 14..18 {
        let mut a = fixture(2);
        a.public[i] = F::from_u128(1u128 << 64);
        derived(&mut a);
        assert!(validate(&a).is_err());
        assert!(!satisfied(a));
    }
}
