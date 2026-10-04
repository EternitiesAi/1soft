use ff::Field;
use halo2_proofs::dev::MockProver;
use shielded_consensus_halo2::{
    circuit::NoteCircuit,
    constants::K,
    field::F,
    fixture::SyntheticFixture,
    relation::Assignment,
};

fn verifies(assignment: Assignment) -> bool {
    let instances = assignment.public_inputs();
    match MockProver::run(K, &NoteCircuit::new(assignment), vec![instances]) {
        Ok(prover) => prover.verify().is_ok(),
        Err(_) => false,
    }
}

#[test]
fn rejects_interval_wrap_and_zero_commitments() {
    let valid = SyntheticFixture::one_note().assignment;
    assert!(verifies(valid.clone()));

    let mut equal_bounds = valid.clone();
    equal_bounds.public.0[5] = equal_bounds.public.0[6];
    equal_bounds.refresh_authorization();
    assert!(!verifies(equal_bounds));

    let mut wrapped = valid.clone();
    wrapped.public.0[5] = F::from(u64::MAX);
    wrapped.public.0[6] = F::ZERO;
    wrapped.refresh_authorization();
    assert!(!verifies(wrapped));

    let mut above_u64 = valid.clone();
    above_u64.public.0[5] = F::from(u64::MAX) + F::ONE;
    above_u64.refresh_authorization();
    assert!(!verifies(above_u64));

    let mut zero_output_0 = valid.clone();
    zero_output_0.public.0[10] = F::ZERO;
    zero_output_0.refresh_authorization();
    assert!(!verifies(zero_output_0));

    let mut zero_output_1 = valid.clone();
    zero_output_1.public.0[11] = F::ZERO;
    zero_output_1.refresh_authorization();
    assert!(!verifies(zero_output_1));

    let mut equal_outputs = valid;
    equal_outputs.public.0[11] = equal_outputs.public.0[10];
    equal_outputs.refresh_authorization();
    assert!(!verifies(equal_outputs));
}

#[test]
fn mutation_matrix_rejects_each_relation_break() {
    let valid = SyntheticFixture::one_note().assignment;
    let mut mutations = Vec::new();

    let mut path = valid.clone();
    path.witness.authentication_path[0] += F::ONE;
    mutations.push(path);

    let mut position = valid.clone();
    position.witness.input_position = 16;
    mutations.push(position);

    let mut balance = valid.clone();
    balance.witness.output_values[0] += 1;
    mutations.push(balance);

    let mut authorization = valid.clone();
    authorization.public.0[13] += F::ONE;
    mutations.push(authorization);

    let mut nullifier = valid.clone();
    nullifier.public.0[9] += F::ONE;
    nullifier.refresh_authorization();
    mutations.push(nullifier);

    let mut input_expiry = valid.clone();
    input_expiry.witness.input_expiry =
        input_expiry.public.valid_until().unwrap() - 1;
    mutations.push(input_expiry);

    let mut output_expiry = valid.clone();
    output_expiry.witness.output_expiries[1] =
        output_expiry.public.valid_until().unwrap() - 1;
    mutations.push(output_expiry);

    let mut spend_secret = valid.clone();
    spend_secret.witness.spend_secret += F::ONE;
    mutations.push(spend_secret);

    let mut output = valid;
    output.public.0[10] += F::ONE;
    output.refresh_authorization();
    mutations.push(output);

    for mutation in mutations {
        assert!(!verifies(mutation));
    }
}

#[test]
fn valid_endpoint_boundaries_satisfy() {
    let mut minimum = SyntheticFixture::one_note().assignment;
    minimum.public.0[5] = F::ZERO;
    minimum.public.0[6] = F::ONE;
    minimum.witness.input_expiry = 1;
    minimum.witness.output_expiries = [1, 1];
    minimum.rebuild_derived().unwrap();
    assert!(verifies(minimum));

    let mut maximum = SyntheticFixture::one_note().assignment;
    maximum.public.0[5] = F::from(u64::MAX - 1);
    maximum.public.0[6] = F::from(u64::MAX);
    maximum.witness.input_expiry = u64::MAX;
    maximum.witness.output_expiries = [u64::MAX, u64::MAX];
    maximum.rebuild_derived().unwrap();
    assert!(verifies(maximum));
}
