use ff::{Field, PrimeField};

use crate::{
    constants::{DEPTH, PUBLIC_INPUT_COUNT, RELATION_VERSION},
    encoding::WitnessV1,
    field::{decode_field, encode_field, FieldBytes, F},
    tree::{native_hash, root_from_path},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicStatement(pub [F; PUBLIC_INPUT_COUNT]);

impl PublicStatement {
    pub fn from_field_bytes(
        bytes: [FieldBytes; PUBLIC_INPUT_COUNT],
    ) -> Result<Self, RelationError> {
        let mut fields = [F::ZERO; PUBLIC_INPUT_COUNT];
        for (target, source) in fields.iter_mut().zip(bytes) {
            *target = decode_field(source).map_err(|_| RelationError::PublicRange)?;
        }
        Ok(Self(fields))
    }

    pub fn to_field_bytes(&self) -> [FieldBytes; PUBLIC_INPUT_COUNT] {
        self.0.map(encode_field)
    }

    pub fn relation_version(&self) -> Result<u64, RelationError> {
        field_to_u64(self.0[0])
    }

    pub fn authority_epoch(&self) -> Result<u64, RelationError> {
        field_to_u64(self.0[4])
    }

    pub fn valid_from(&self) -> Result<u64, RelationError> {
        field_to_u64(self.0[5])
    }

    pub fn valid_until(&self) -> Result<u64, RelationError> {
        field_to_u64(self.0[6])
    }

    pub fn fee(&self) -> Result<u64, RelationError> {
        field_to_u64(self.0[12])
    }

    pub fn validate_shape(&self) -> Result<(), RelationError> {
        if self.relation_version()? != u64::from(RELATION_VERSION) {
            return Err(RelationError::WrongRelation);
        }
        self.authority_epoch()?;
        let valid_from = self.valid_from()?;
        let valid_until = self.valid_until()?;
        self.fee()?;
        if valid_from >= valid_until {
            return Err(RelationError::ValidityInterval);
        }
        if bool::from(self.0[10].is_zero())
            || bool::from(self.0[11].is_zero())
            || self.0[10] == self.0[11]
        {
            return Err(RelationError::OutputCommitment);
        }
        if authorization_digest(self) != self.0[13] {
            return Err(RelationError::Authorization);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpendWitness {
    pub input_position: u16,
    pub input_value: u64,
    pub input_expiry: u64,
    pub input_blinding: F,
    pub spend_secret: F,
    pub note_secret: F,
    pub authentication_path: [F; DEPTH],
    pub output_values: [u64; 2],
    pub output_expiries: [u64; 2],
    pub output_recipient_keys: [F; 2],
    pub output_note_secrets: [F; 2],
    pub output_blindings: [F; 2],
}

impl TryFrom<WitnessV1> for SpendWitness {
    type Error = RelationError;

    fn try_from(witness: WitnessV1) -> Result<Self, Self::Error> {
        let field = |bytes| decode_field(bytes).map_err(|_| RelationError::WitnessField);
        Ok(Self {
            input_position: witness.input_position,
            input_value: witness.input_value,
            input_expiry: witness.input_expiry,
            input_blinding: field(witness.input_blinding)?,
            spend_secret: field(witness.spend_secret)?,
            note_secret: field(witness.note_secret)?,
            authentication_path: witness
                .authentication_path
                .map(field)
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .map_err(|_| RelationError::WitnessField)?,
            output_values: witness.output_values,
            output_expiries: witness.output_expiries,
            output_recipient_keys: witness
                .output_recipient_keys
                .map(field)
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .map_err(|_| RelationError::WitnessField)?,
            output_note_secrets: witness
                .output_note_secrets
                .map(field)
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .map_err(|_| RelationError::WitnessField)?,
            output_blindings: witness
                .output_blindings
                .map(field)
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .map_err(|_| RelationError::WitnessField)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Assignment {
    pub public: PublicStatement,
    pub witness: SpendWitness,
}

impl Assignment {
    pub fn public_inputs(&self) -> Vec<F> {
        self.public.0.to_vec()
    }

    pub fn refresh_authorization(&mut self) {
        self.public.0[13] = authorization_digest(&self.public);
    }

    pub fn rebuild_derived(&mut self) -> Result<(), RelationError> {
        let input = input_commitment(self);
        self.public.0[8] = root_from_path(
            input,
            usize::from(self.witness.input_position),
            self.witness.authentication_path,
        )
        .map_err(|_| RelationError::AnchorRoot)?;
        self.public.0[9] = nullifier(self, input);
        self.public.0[10] = output_commitment(self, 0);
        self.public.0[11] = output_commitment(self, 1);
        self.refresh_authorization();
        validate_native(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelationError {
    WrongRelation,
    PublicRange,
    ValidityInterval,
    NoteExpiry,
    Value,
    Balance,
    WitnessField,
    InputCommitment,
    AnchorRoot,
    Nullifier,
    OutputCommitment,
    Authorization,
}

pub fn field_to_u64(value: F) -> Result<u64, RelationError> {
    let bytes = value.to_repr();
    if bytes[8..].iter().any(|byte| *byte != 0) {
        return Err(RelationError::PublicRange);
    }
    Ok(u64::from_le_bytes(
        bytes[..8].try_into().expect("eight-byte slice"),
    ))
}

pub fn spend_key(spend_secret: F) -> F {
    native_hash([F::from(106), spend_secret])
}

pub fn note_commitment(
    public: &PublicStatement,
    expiry: u64,
    value: u64,
    owner_key: F,
    note_secret: F,
    blinding: F,
) -> F {
    native_hash([
        F::from(100),
        public.0[0],
        public.0[1],
        public.0[2],
        public.0[3],
        public.0[4],
        public.0[7],
        F::from(expiry),
        F::from(value),
        owner_key,
        note_secret,
        blinding,
    ])
}

pub fn input_commitment(assignment: &Assignment) -> F {
    note_commitment(
        &assignment.public,
        assignment.witness.input_expiry,
        assignment.witness.input_value,
        spend_key(assignment.witness.spend_secret),
        assignment.witness.note_secret,
        assignment.witness.input_blinding,
    )
}

pub fn nullifier(assignment: &Assignment, input: F) -> F {
    native_hash([
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
    ])
}

pub fn output_commitment(assignment: &Assignment, index: usize) -> F {
    note_commitment(
        &assignment.public,
        assignment.witness.output_expiries[index],
        assignment.witness.output_values[index],
        assignment.witness.output_recipient_keys[index],
        assignment.witness.output_note_secrets[index],
        assignment.witness.output_blindings[index],
    )
}

pub fn authorization_digest(public: &PublicStatement) -> F {
    native_hash([
        F::from(105),
        public.0[0],
        public.0[1],
        public.0[2],
        public.0[3],
        public.0[4],
        public.0[5],
        public.0[6],
        public.0[7],
        public.0[8],
        public.0[9],
        public.0[10],
        public.0[11],
        public.0[12],
    ])
}

pub fn validate_native(assignment: &Assignment) -> Result<(), RelationError> {
    if assignment.public.relation_version()? != u64::from(RELATION_VERSION) {
        return Err(RelationError::WrongRelation);
    }
    assignment.public.authority_epoch()?;
    let valid_from = assignment.public.valid_from()?;
    let valid_until = assignment.public.valid_until()?;
    let fee = assignment.public.fee()?;
    if valid_from >= valid_until {
        return Err(RelationError::ValidityInterval);
    }

    if assignment.witness.input_expiry < valid_until
        || assignment.witness.output_expiries[0] < valid_until
        || assignment.witness.output_expiries[1] < valid_until
    {
        return Err(RelationError::NoteExpiry);
    }
    if assignment.witness.input_value == 0
        || assignment.witness.output_values[0] == 0
        || assignment.witness.output_values[1] == 0
    {
        return Err(RelationError::Value);
    }
    let outputs = assignment.witness.output_values[0]
        .checked_add(assignment.witness.output_values[1])
        .and_then(|value| value.checked_add(fee))
        .ok_or(RelationError::Balance)?;
    if outputs != assignment.witness.input_value {
        return Err(RelationError::Balance);
    }

    let input = input_commitment(assignment);
    if bool::from(input.is_zero()) {
        return Err(RelationError::InputCommitment);
    }
    let root = root_from_path(
        input,
        usize::from(assignment.witness.input_position),
        assignment.witness.authentication_path,
    )
    .map_err(|_| RelationError::AnchorRoot)?;
    if root != assignment.public.0[8] {
        return Err(RelationError::AnchorRoot);
    }

    let expected_nullifier = nullifier(assignment, input);
    if expected_nullifier != assignment.public.0[9] {
        return Err(RelationError::Nullifier);
    }

    let output_0 = output_commitment(assignment, 0);
    let output_1 = output_commitment(assignment, 1);
    if bool::from(output_0.is_zero())
        || bool::from(output_1.is_zero())
        || output_0 == output_1
        || output_0 != assignment.public.0[10]
        || output_1 != assignment.public.0[11]
    {
        return Err(RelationError::OutputCommitment);
    }

    if authorization_digest(&assignment.public) != assignment.public.0[13] {
        return Err(RelationError::Authorization);
    }
    Ok(())
}
