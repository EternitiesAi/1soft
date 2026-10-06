use ff::{Field, PrimeField};
use halo2_proofs::dev::MockProver;
use recipient_transfer::{circuit::TransferCircuit, fixtures, relation as r, F, K};
fn circuit_valid(a: r::Assignment) -> bool {
    match MockProver::run(K, &TransferCircuit::new(a.clone()), vec![a.public.to_vec()]) {
        Ok(p) => p.verify().is_ok(),
        Err(_) => false,
    }
}
fn trusted_root(a: &r::Assignment, mut b: r::Assignment) -> r::Assignment {
    r::derive(&mut b);
    b.public[4] = a.public[4];
    b.public[12] = r::binding(&b.public);
    b
}
#[test]
fn valid_recipient_transfer_and_re_spend() {
    let a = fixtures::first([1; 32]);
    let b = fixtures::second(&a);
    assert!(r::validate(&a).is_ok());
    assert!(r::validate(&b).is_ok());
    assert_eq!(r::input(&b), a.public[10]);
    assert_eq!(b.witness.input_value, a.witness.payment);
    assert_ne!(a.public[5], b.public[5]);
    assert!(circuit_valid(a));
    assert!(circuit_valid(b));
}
#[test]
fn ownership_opening_path_and_domains_cannot_be_forged() {
    let a = fixtures::first([1; 32]);
    let mut cases = Vec::new();
    for k in 0..6 {
        let mut b = a.clone();
        match k {
            0 => b.witness.recipient_secret = F::from(77),
            1 => b.witness.input_origin = F::from(77),
            2 => b.witness.input_value += 1,
            3 => b.witness.input_expiry += 1,
            4 => b.witness.input_secret = F::from(77),
            _ => b.witness.input_blind = F::from(77),
        }
        cases.push(trusted_root(&a, b));
    }
    for k in 0..4 {
        let mut b = a.clone();
        b.witness.path[k] = F::from(77);
        cases.push(trusted_root(&a, b));
    }
    let mut b = a.clone();
    b.witness.position = 1;
    cases.push(trusted_root(&a, b));
    for k in [1, 2, 3] {
        let mut b = a.clone();
        b.public[k] = F::from(77);
        cases.push(trusted_root(&a, b));
    }
    for b in cases {
        assert!(!circuit_valid(b));
    }
}
#[test]
fn conservation_expiry_zero_and_ranges_are_circuit_constraints() {
    let a = fixtures::first([1; 32]);
    let mut cases = Vec::new();
    for k in 0..14 {
        let mut b = a.clone();
        match k {
            0 => b.witness.payment += 1,
            1 => b.witness.change += 1,
            2 => b.witness.payment = 0,
            3 => b.witness.change = 0,
            4 => b.witness.payment_expiry = 7,
            5 => b.witness.payment_expiry = 65,
            6 => b.public[7] = F::ZERO,
            7 => b.public[8] = b.public[7],
            8 => b.public[9] = F::ZERO,
            9 => b.public[9] = F::from_u128(1u128 << 64),
            10 => b.witness.position = 16,
            11 => b.witness.payment_secret = F::ZERO,
            12 => b.witness.destination = F::ZERO,
            _ => b.witness.change_blind = F::ZERO,
        }
        cases.push(trusted_root(&a, b));
    }
    let mut b = a.clone();
    b.witness.input_value = u64::MAX;
    b.witness.payment = u64::MAX;
    b.witness.change = 1;
    b.witness.path = r::tree(&[r::input(&b)]).unwrap().1[0];
    r::derive(&mut b);
    cases.push(b);
    for b in cases {
        assert!(!circuit_valid(b));
    }
    let mut boundary = a;
    boundary.witness.input_value = u64::MAX;
    boundary.witness.payment = u64::MAX - 2;
    boundary.witness.change = 1;
    boundary.witness.path = r::tree(&[r::input(&boundary)]).unwrap().1[0];
    r::derive(&mut boundary);
    assert!(r::validate(&boundary).is_ok());
    assert!(circuit_valid(boundary));
}
#[test]
fn nullifier_is_independent_of_intent_and_duplicate_position() {
    let a = fixtures::first([1; 32]);
    let original = r::nullifier(&a);
    let mut b = a.clone();
    b.witness.position = 15;
    b.public[6] = F::from(888);
    assert_eq!(r::nullifier(&b), original);
    b.witness.recipient_secret = F::from(99);
    assert_ne!(r::nullifier(&b), original);
    // Even a manually duplicated leaf has the same nullifier in two valid paths.
    let n = r::input(&a);
    let mut nodes = vec![r::leaf(F::ZERO); 16];
    nodes[0] = r::leaf(n);
    nodes[1] = r::leaf(n);
    let mut paths = [[F::ZERO; 4]; 2];
    for d in 0..4 {
        for i in 0..2 {
            paths[i][d] = nodes[(i >> d) ^ 1]
        }
        nodes = nodes
            .chunks_exact(2)
            .map(|v| r::branch(v[0], v[1]))
            .collect();
    }
    let mut x = a.clone();
    x.witness.path = paths[0];
    r::derive(&mut x);
    let mut y = a;
    y.witness.path = paths[1];
    y.witness.position = 1;
    r::derive(&mut y);
    assert_eq!(x.public[4], y.public[4]);
    assert_eq!(x.public[5], y.public[5]);
    assert!(circuit_valid(x));
    assert!(circuit_valid(y));
    assert!(r::tree(&[n, n]).is_err());
}
#[test]
fn independent_u128_value_oracle_and_public_tampering() {
    let a = fixtures::first([1; 32]);
    let mut checked = 0;
    for value in 2u64..20 {
        for pay in 1..value {
            let mut b = a.clone();
            b.witness.input_value = value;
            b.witness.payment = pay;
            b.witness.change = 1;
            b.witness.path = r::tree(&[r::input(&b)]).unwrap().1[0];
            r::derive(&mut b);
            let expected = u128::from(value) == u128::from(pay) + 1 + 1;
            assert_eq!(r::validate(&b).is_ok(), expected);
            checked += 1;
        }
    }
    assert_eq!(checked, 171);
    for i in 0..13 {
        let mut b = a.clone();
        b.public[i] += F::ONE;
        assert!(!circuit_valid(b));
    }
}
