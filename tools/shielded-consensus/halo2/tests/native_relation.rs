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

#[test]
fn public_statement_does_not_invent_zero_nullifier_rule() {
    let mut assignment = SyntheticFixture::one_note().assignment;
    assignment.public.0[9] = F::ZERO;
    assignment.refresh_authorization();
    assert_eq!(assignment.public.validate_shape(), Ok(()));
    assert_eq!(
        validate_native(&assignment),
        Err(RelationError::Nullifier),
        "native relation still requires equality with the derived nullifier"
    );
}

#[test]
fn poseidon_relations_match_frozen_argument_order_and_outputs() {
    use std::{fs, path::PathBuf};

    use serde_json::Value;
    use shielded_consensus_halo2::{
        field::encode_field,
        relation::{
            authorization_digest, input_commitment, nullifier, output_commitment, spend_key,
        },
    };

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../test-vectors/crypto-v1.json");
    let vectors: Value =
        serde_json::from_slice(&fs::read(path).expect("read vectors")).expect("parse vectors");
    let expected = &vectors["relation"];
    let assignment = SyntheticFixture::one_note().assignment;
    let input = input_commitment(&assignment);
    let key = spend_key(assignment.witness.spend_secret);
    let output_0 = output_commitment(&assignment, 0);
    let output_1 = output_commitment(&assignment, 1);
    let derived_nullifier = nullifier(&assignment, input);
    let authorization = authorization_digest(&assignment.public);
    let hex_fields = |values: &[F]| {
        values
            .iter()
            .map(|value| Value::String(hex::encode(encode_field(*value))))
            .collect::<Vec<_>>()
    };

    assert_eq!(
        hex_fields(&[F::from(106), assignment.witness.spend_secret]),
        *expected["spend_key_args"].as_array().unwrap()
    );
    assert_eq!(hex::encode(encode_field(key)), expected["spend_key"]);

    assert_eq!(
        hex_fields(&[
            F::from(100),
            assignment.public.0[0],
            assignment.public.0[1],
            assignment.public.0[2],
            assignment.public.0[3],
            assignment.public.0[4],
            assignment.public.0[7],
            F::from(assignment.witness.input_expiry),
            F::from(assignment.witness.input_value),
            key,
            assignment.witness.note_secret,
            assignment.witness.input_blinding,
        ]),
        *expected["input_commitment_args"].as_array().unwrap()
    );
    assert_eq!(
        hex::encode(encode_field(input)),
        expected["input_commitment"]
    );

    assert_eq!(
        hex_fields(&[
            F::from(103),
            assignment.public.0[0],
            assignment.public.0[1],
            assignment.public.0[2],
            assignment.public.0[3],
            assignment.public.0[4],
            assignment.public.0[7],
            assignment.witness.spend_secret,
            assignment.witness.note_secret,
            input,
            F::from(u64::from(assignment.witness.input_position)),
        ]),
        *expected["nullifier_args"].as_array().unwrap()
    );
    assert_eq!(
        hex::encode(encode_field(derived_nullifier)),
        expected["nullifier"]
    );

    assert_eq!(
        hex_fields(&[
            F::from(105),
            assignment.public.0[0],
            assignment.public.0[1],
            assignment.public.0[2],
            assignment.public.0[3],
            assignment.public.0[4],
            assignment.public.0[5],
            assignment.public.0[6],
            assignment.public.0[7],
            assignment.public.0[8],
            assignment.public.0[9],
            assignment.public.0[10],
            assignment.public.0[11],
            assignment.public.0[12],
        ]),
        *expected["authorization_args"].as_array().unwrap()
    );
    assert_eq!(
        hex::encode(encode_field(authorization)),
        expected["authorization"]
    );
    assert_eq!(
        [output_0, output_1]
            .map(|value| Value::String(hex::encode(encode_field(value))))
            .to_vec(),
        *expected["output_commitments"].as_array().unwrap()
    );
    assert_eq!(
        hex_fields(&assignment.public.0),
        *expected["public_inputs"].as_array().unwrap()
    );
}
