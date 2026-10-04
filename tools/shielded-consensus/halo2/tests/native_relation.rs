use ff::Field;
use shielded_consensus_halo2::{
    field::F,
    fixture::SyntheticFixture,
    relation::{validate_native, RelationError},
};

#[test]
fn native_relation_accepts_fixture_and_rejects_isolated_mutations() {
    let fixture = SyntheticFixture::one_note();
    assert_eq!(validate_native(&fixture.assignment), Ok(()));

    let mut wrong_path = fixture.assignment.clone();
    wrong_path.witness.authentication_path[0] += F::ONE;
    assert_eq!(validate_native(&wrong_path), Err(RelationError::AnchorRoot));

    let mut wrong_nullifier = fixture.assignment.clone();
    wrong_nullifier.public.0[9] += F::ONE;
    wrong_nullifier.refresh_authorization();
    assert_eq!(validate_native(&wrong_nullifier), Err(RelationError::Nullifier));

    let mut wrong_balance = fixture.assignment.clone();
    wrong_balance.witness.output_values[0] += 1;
    assert_eq!(validate_native(&wrong_balance), Err(RelationError::Balance));

    let mut invalid_interval = fixture.assignment.clone();
    invalid_interval.public.0[5] = invalid_interval.public.0[6];
    invalid_interval.refresh_authorization();
    assert_eq!(
        validate_native(&invalid_interval),
        Err(RelationError::ValidityInterval)
    );

    let mut expired_input = fixture.assignment.clone();
    expired_input.witness.input_expiry = 199;
    assert_eq!(
        validate_native(&expired_input),
        Err(RelationError::NoteExpiry)
    );

    let mut zero_output = fixture.assignment.clone();
    zero_output.public.0[10] = F::ZERO;
    zero_output.refresh_authorization();
    assert_eq!(
        validate_native(&zero_output),
        Err(RelationError::OutputCommitment)
    );

    let mut equal_outputs = fixture.assignment.clone();
    equal_outputs.public.0[11] = equal_outputs.public.0[10];
    equal_outputs.refresh_authorization();
    assert_eq!(
        validate_native(&equal_outputs),
        Err(RelationError::OutputCommitment)
    );
}
