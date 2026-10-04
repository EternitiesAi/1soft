use ff::Field;

use crate::{
    constants::{DEPTH, PUBLIC_INPUT_COUNT, RELATION_VERSION},
    encoding::WitnessV1,
    field::{encode_field, F},
    relation::{
        input_commitment, nullifier, output_commitment, validate_native, Assignment,
        PublicStatement, SpendWitness,
    },
    tree::{authentication_path, native_hash, tree_root},
};

#[derive(Clone, Debug)]
pub struct SyntheticFixture {
    pub assignment: Assignment,
    pub commitments: Vec<F>,
}

impl SyntheticFixture {
    pub fn one_note() -> Self {
        let mut public = [F::ZERO; PUBLIC_INPUT_COUNT];
        public[0] = F::from(u64::from(RELATION_VERSION));
        public[1] = F::from(11);
        public[2] = F::from(12);
        public[3] = F::from(13);
        public[4] = F::from(2);
        public[5] = F::from(100);
        public[6] = F::from(200);
        public[7] = F::from(14);
        public[12] = F::from(1);

        let mut assignment = Assignment {
            public: PublicStatement(public),
            witness: SpendWitness {
                input_position: 0,
                input_value: 100,
                input_expiry: 300,
                input_blinding: F::from(21),
                spend_secret: F::from(22),
                note_secret: F::from(23),
                authentication_path: [F::ZERO; DEPTH],
                output_values: [40, 59],
                output_expiries: [400, 500],
                output_recipient_keys: [
                    native_hash([F::from(106), F::from(33)]),
                    native_hash([F::from(106), F::from(43)]),
                ],
                output_note_secrets: [F::from(34), F::from(44)],
                output_blindings: [F::from(32), F::from(42)],
            },
        };

        let input = input_commitment(&assignment);
        let commitments = vec![input];
        assignment.witness.authentication_path =
            authentication_path(&commitments, 0).expect("synthetic authentication path");
        assignment.public.0[8] = tree_root(&commitments).expect("synthetic root");
        assignment.public.0[9] = nullifier(&assignment, input);
        assignment.public.0[10] = output_commitment(&assignment, 0);
        assignment.public.0[11] = output_commitment(&assignment, 1);
        assignment.refresh_authorization();
        validate_native(&assignment).expect("synthetic fixture must satisfy native relation");
        Self {
            assignment,
            commitments,
        }
    }

    pub fn witness_wire(&self) -> WitnessV1 {
        WitnessV1 {
            input_position: self.assignment.witness.input_position,
            input_value: self.assignment.witness.input_value,
            input_expiry: self.assignment.witness.input_expiry,
            input_blinding: encode_field(self.assignment.witness.input_blinding),
            spend_secret: encode_field(self.assignment.witness.spend_secret),
            note_secret: encode_field(self.assignment.witness.note_secret),
            authentication_path: self
                .assignment
                .witness
                .authentication_path
                .map(encode_field),
            output_values: self.assignment.witness.output_values,
            output_expiries: self.assignment.witness.output_expiries,
            output_recipient_keys: self
                .assignment
                .witness
                .output_recipient_keys
                .map(encode_field),
            output_note_secrets: self
                .assignment
                .witness
                .output_note_secrets
                .map(encode_field),
            output_blindings: self
                .assignment
                .witness
                .output_blindings
                .map(encode_field),
        }
    }
}
