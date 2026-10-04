use std::fmt;

use ff::Field;

use crate::{
    constants::{CAPACITY, PUBLIC_INPUT_COUNT, RELATION_VERSION},
    encoding::{Digest32, EncodingError, ProverRequestV1, WitnessV1},
    field::{decode_field, encode_field, FieldBytes, F},
    relation::{
        field_to_u64, input_commitment, note_commitment, spend_key, Assignment, PublicStatement,
        SpendWitness,
    },
    tree::{authentication_path, tree_root},
};

const CLIENT_MAGIC: [u8; 8] = *b"1SFTCLI1";
const GENESIS_OUTPUT_MAGIC: [u8; 8] = *b"1SFTGEN1";
const CLIENT_VERSION: u16 = 1;
const GENESIS_OPCODE: u16 = 1;
const SPEND_OPCODE: u16 = 2;
pub const MAX_CLIENT_REQUEST_BYTES: usize = 1966;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteDomainV1 {
    pub genesis_field: FieldBytes,
    pub asset_field: FieldBytes,
    pub context_field: FieldBytes,
    pub authority_epoch: FieldBytes,
    pub policy_field: FieldBytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpendHeaderV1 {
    pub domain: NoteDomainV1,
    pub valid_from: FieldBytes,
    pub valid_until: FieldBytes,
    pub fee: FieldBytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NoteDefinitionV1 {
    pub expiry: u64,
    pub value: u64,
    pub owner_spend_secret: FieldBytes,
    pub note_secret: FieldBytes,
    pub blinding: FieldBytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DevelopmentClientRequestV1 {
    GenesisCommitments {
        domain: NoteDomainV1,
        notes: Vec<NoteDefinitionV1>,
    },
    Spend {
        genesis_sha256: Digest32,
        deployment_id: Digest32,
        header: SpendHeaderV1,
        commitments: Vec<FieldBytes>,
        input_position: u16,
        input_note: NoteDefinitionV1,
        outputs: [NoteDefinitionV1; 2],
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GenesisCommitmentsV1 {
    pub commitments: Vec<FieldBytes>,
    pub root: FieldBytes,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DevelopmentClientOutputV1 {
    Genesis(GenesisCommitmentsV1),
    ProverRequest(ProverRequestV1),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientError {
    Encoding(EncodingError),
    InvalidRequest,
}

impl fmt::Display for ClientError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(error) => write!(formatter, "{error}"),
            Self::InvalidRequest => formatter.write_str("invalid development-client request"),
        }
    }
}

impl From<EncodingError> for ClientError {
    fn from(value: EncodingError) -> Self {
        Self::Encoding(value)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self { Self { bytes, offset: 0 } }
    fn take(&mut self, length: usize) -> Result<&'a [u8], EncodingError> {
        let end = self.offset.checked_add(length).ok_or(EncodingError::InvalidLength)?;
        if end > self.bytes.len() { return Err(EncodingError::Truncated); }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], EncodingError> {
        self.take(N)?.try_into().map_err(|_| EncodingError::Truncated)
    }
    fn u16(&mut self) -> Result<u16, EncodingError> { Ok(u16::from_le_bytes(self.array()?)) }
    fn u64(&mut self) -> Result<u64, EncodingError> { Ok(u64::from_le_bytes(self.array()?)) }
    fn field(&mut self) -> Result<FieldBytes, EncodingError> {
        let bytes = self.array()?;
        decode_field(bytes).map_err(|_| EncodingError::InvalidField)?;
        Ok(bytes)
    }
    fn finish(self) -> Result<(), EncodingError> {
        if self.offset == self.bytes.len() { Ok(()) } else { Err(EncodingError::TrailingBytes) }
    }
}

fn push_u16(output: &mut Vec<u8>, value: u16) { output.extend_from_slice(&value.to_le_bytes()); }
fn push_u64(output: &mut Vec<u8>, value: u64) { output.extend_from_slice(&value.to_le_bytes()); }
fn push_field(output: &mut Vec<u8>, value: FieldBytes) -> Result<(), EncodingError> {
    decode_field(value).map_err(|_| EncodingError::InvalidField)?;
    output.extend_from_slice(&value);
    Ok(())
}

impl NoteDomainV1 {
    fn encode_into(&self, output: &mut Vec<u8>) -> Result<(), EncodingError> {
        for value in [self.genesis_field, self.asset_field, self.context_field, self.authority_epoch, self.policy_field] {
            push_field(output, value)?;
        }
        Ok(())
    }
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, EncodingError> {
        Ok(Self {
            genesis_field: reader.field()?,
            asset_field: reader.field()?,
            context_field: reader.field()?,
            authority_epoch: reader.field()?,
            policy_field: reader.field()?,
        })
    }
    fn public_statement(&self) -> Result<PublicStatement, ClientError> {
        let mut public = [F::ZERO; PUBLIC_INPUT_COUNT];
        public[0] = F::from(u64::from(RELATION_VERSION));
        for (slot, bytes) in [
            (1, self.genesis_field),
            (2, self.asset_field),
            (3, self.context_field),
            (4, self.authority_epoch),
            (7, self.policy_field),
        ] {
            public[slot] = decode_field(bytes).map_err(|_| ClientError::InvalidRequest)?;
        }
        field_to_u64(public[4]).map_err(|_| ClientError::InvalidRequest)?;
        Ok(PublicStatement(public))
    }
}

impl SpendHeaderV1 {
    fn encode_into(&self, output: &mut Vec<u8>) -> Result<(), EncodingError> {
        self.domain.encode_into(output)?;
        for value in [self.valid_from, self.valid_until, self.fee] { push_field(output, value)?; }
        Ok(())
    }
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, EncodingError> {
        Ok(Self {
            domain: NoteDomainV1::decode_from(reader)?,
            valid_from: reader.field()?,
            valid_until: reader.field()?,
            fee: reader.field()?,
        })
    }
    fn public_statement(&self) -> Result<PublicStatement, ClientError> {
        let mut public = self.domain.public_statement()?;
        public.0[5] = decode_field(self.valid_from).map_err(|_| ClientError::InvalidRequest)?;
        public.0[6] = decode_field(self.valid_until).map_err(|_| ClientError::InvalidRequest)?;
        public.0[12] = decode_field(self.fee).map_err(|_| ClientError::InvalidRequest)?;
        Ok(public)
    }
}

impl NoteDefinitionV1 {
    fn encode_into(&self, output: &mut Vec<u8>) -> Result<(), EncodingError> {
        push_u64(output, self.expiry);
        push_u64(output, self.value);
        for value in [self.owner_spend_secret, self.note_secret, self.blinding] { push_field(output, value)?; }
        Ok(())
    }
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, EncodingError> {
        Ok(Self {
            expiry: reader.u64()?,
            value: reader.u64()?,
            owner_spend_secret: reader.field()?,
            note_secret: reader.field()?,
            blinding: reader.field()?,
        })
    }
    fn fields(&self) -> Result<(F, F, F), ClientError> {
        Ok((
            decode_field(self.owner_spend_secret).map_err(|_| ClientError::InvalidRequest)?,
            decode_field(self.note_secret).map_err(|_| ClientError::InvalidRequest)?,
            decode_field(self.blinding).map_err(|_| ClientError::InvalidRequest)?,
        ))
    }
}

impl DevelopmentClientRequestV1 {
    pub fn encode(&self) -> Result<Vec<u8>, EncodingError> {
        let mut output = Vec::with_capacity(MAX_CLIENT_REQUEST_BYTES);
        output.extend_from_slice(&CLIENT_MAGIC);
        push_u16(&mut output, CLIENT_VERSION);
        match self {
            Self::GenesisCommitments { domain, notes } => {
                if notes.is_empty() || notes.len() > CAPACITY { return Err(EncodingError::LimitExceeded); }
                push_u16(&mut output, GENESIS_OPCODE);
                domain.encode_into(&mut output)?;
                push_u16(&mut output, notes.len() as u16);
                for note in notes { note.encode_into(&mut output)?; }
            }
            Self::Spend { genesis_sha256, deployment_id, header, commitments, input_position, input_note, outputs } => {
                if commitments.is_empty() || commitments.len() > CAPACITY - 2 || usize::from(*input_position) >= commitments.len() {
                    return Err(EncodingError::LimitExceeded);
                }
                push_u16(&mut output, SPEND_OPCODE);
                output.extend_from_slice(genesis_sha256);
                output.extend_from_slice(deployment_id);
                header.encode_into(&mut output)?;
                push_u16(&mut output, commitments.len() as u16);
                for commitment in commitments { push_field(&mut output, *commitment)?; }
                push_u16(&mut output, *input_position);
                input_note.encode_into(&mut output)?;
                for note in outputs { note.encode_into(&mut output)?; }
            }
        }
        if output.len() > MAX_CLIENT_REQUEST_BYTES { return Err(EncodingError::LimitExceeded); }
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EncodingError> {
        if bytes.len() > MAX_CLIENT_REQUEST_BYTES { return Err(EncodingError::LimitExceeded); }
        let mut reader = Reader::new(bytes);
        if reader.array::<8>()? != CLIENT_MAGIC { return Err(EncodingError::WrongMagic); }
        if reader.u16()? != CLIENT_VERSION { return Err(EncodingError::WrongVersion); }
        let request = match reader.u16()? {
            GENESIS_OPCODE => {
                let domain = NoteDomainV1::decode_from(&mut reader)?;
                let count = usize::from(reader.u16()?);
                if count == 0 || count > CAPACITY { return Err(EncodingError::LimitExceeded); }
                let mut notes = Vec::with_capacity(count);
                for _ in 0..count { notes.push(NoteDefinitionV1::decode_from(&mut reader)?); }
                Self::GenesisCommitments { domain, notes }
            }
            SPEND_OPCODE => {
                let genesis_sha256 = reader.array()?;
                let deployment_id = reader.array()?;
                let header = SpendHeaderV1::decode_from(&mut reader)?;
                let count = usize::from(reader.u16()?);
                if count == 0 || count > CAPACITY - 2 { return Err(EncodingError::LimitExceeded); }
                let mut commitments = Vec::with_capacity(count);
                for _ in 0..count { commitments.push(reader.field()?); }
                let input_position = reader.u16()?;
                if usize::from(input_position) >= count { return Err(EncodingError::InvalidValue); }
                let input_note = NoteDefinitionV1::decode_from(&mut reader)?;
                let outputs = [NoteDefinitionV1::decode_from(&mut reader)?, NoteDefinitionV1::decode_from(&mut reader)?];
                Self::Spend { genesis_sha256, deployment_id, header, commitments, input_position, input_note, outputs }
            }
            _ => return Err(EncodingError::InvalidValue),
        };
        reader.finish()?;
        if request.encode()?.len() != bytes.len() { return Err(EncodingError::InvalidLength); }
        Ok(request)
    }

    pub fn derive(&self) -> Result<DevelopmentClientOutputV1, ClientError> {
        match self {
            Self::GenesisCommitments { domain, notes } => {
                let public = domain.public_statement()?;
                let mut commitments = Vec::with_capacity(notes.len());
                for note in notes {
                    if note.value == 0 { return Err(ClientError::InvalidRequest); }
                    let (owner_secret, note_secret, blinding) = note.fields()?;
                    let commitment = note_commitment(&public, note.expiry, note.value, spend_key(owner_secret), note_secret, blinding);
                    if bool::from(commitment.is_zero()) { return Err(ClientError::InvalidRequest); }
                    commitments.push(commitment);
                }
                let root = tree_root(&commitments).map_err(|_| ClientError::InvalidRequest)?;
                Ok(DevelopmentClientOutputV1::Genesis(GenesisCommitmentsV1 {
                    commitments: commitments.into_iter().map(encode_field).collect(),
                    root: encode_field(root),
                }))
            }
            Self::Spend { genesis_sha256, deployment_id, header, commitments, input_position, input_note, outputs } => {
                let commitment_fields = commitments.iter().map(|value| decode_field(*value).map_err(|_| ClientError::InvalidRequest)).collect::<Result<Vec<_>, _>>()?;
                let mut public = header.public_statement()?;
                let (spend_secret, note_secret, input_blinding) = input_note.fields()?;
                let (output_secret_0, output_note_0, output_blinding_0) = outputs[0].fields()?;
                let (output_secret_1, output_note_1, output_blinding_1) = outputs[1].fields()?;
                let path = authentication_path(&commitment_fields, usize::from(*input_position)).map_err(|_| ClientError::InvalidRequest)?;
                let mut assignment = Assignment {
                    public: public.clone(),
                    witness: SpendWitness {
                        input_position: *input_position,
                        input_value: input_note.value,
                        input_expiry: input_note.expiry,
                        input_blinding,
                        spend_secret,
                        note_secret,
                        authentication_path: path,
                        output_values: [outputs[0].value, outputs[1].value],
                        output_expiries: [outputs[0].expiry, outputs[1].expiry],
                        output_recipient_keys: [spend_key(output_secret_0), spend_key(output_secret_1)],
                        output_note_secrets: [output_note_0, output_note_1],
                        output_blindings: [output_blinding_0, output_blinding_1],
                    },
                };
                if input_commitment(&assignment) != commitment_fields[usize::from(*input_position)] {
                    return Err(ClientError::InvalidRequest);
                }
                assignment.rebuild_derived().map_err(|_| ClientError::InvalidRequest)?;
                if assignment.public.0[8] != tree_root(&commitment_fields).map_err(|_| ClientError::InvalidRequest)? {
                    return Err(ClientError::InvalidRequest);
                }
                public = assignment.public.clone();
                let witness = WitnessV1 {
                    input_position: assignment.witness.input_position,
                    input_value: assignment.witness.input_value,
                    input_expiry: assignment.witness.input_expiry,
                    input_blinding: encode_field(assignment.witness.input_blinding),
                    spend_secret: encode_field(assignment.witness.spend_secret),
                    note_secret: encode_field(assignment.witness.note_secret),
                    authentication_path: assignment.witness.authentication_path.map(encode_field),
                    output_values: assignment.witness.output_values,
                    output_expiries: assignment.witness.output_expiries,
                    output_recipient_keys: assignment.witness.output_recipient_keys.map(encode_field),
                    output_note_secrets: assignment.witness.output_note_secrets.map(encode_field),
                    output_blindings: assignment.witness.output_blindings.map(encode_field),
                };
                Ok(DevelopmentClientOutputV1::ProverRequest(ProverRequestV1 {
                    genesis_sha256: *genesis_sha256,
                    deployment_id: *deployment_id,
                    public_inputs: public.to_field_bytes(),
                    witness,
                }))
            }
        }
    }
}

impl GenesisCommitmentsV1 {
    pub fn encode(&self) -> Result<Vec<u8>, EncodingError> {
        if self.commitments.is_empty() || self.commitments.len() > CAPACITY { return Err(EncodingError::LimitExceeded); }
        let mut output = Vec::with_capacity(44 + self.commitments.len() * 32);
        output.extend_from_slice(&GENESIS_OUTPUT_MAGIC);
        push_u16(&mut output, CLIENT_VERSION);
        push_u16(&mut output, self.commitments.len() as u16);
        for commitment in &self.commitments { push_field(&mut output, *commitment)?; }
        push_field(&mut output, self.root)?;
        Ok(output)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, EncodingError> {
        let mut reader = Reader::new(bytes);
        if reader.array::<8>()? != GENESIS_OUTPUT_MAGIC { return Err(EncodingError::WrongMagic); }
        if reader.u16()? != CLIENT_VERSION { return Err(EncodingError::WrongVersion); }
        let count = usize::from(reader.u16()?);
        if count == 0 || count > CAPACITY { return Err(EncodingError::LimitExceeded); }
        let mut commitments = Vec::with_capacity(count);
        for _ in 0..count { commitments.push(reader.field()?); }
        let root = reader.field()?;
        reader.finish()?;
        Ok(Self { commitments, root })
    }
}

impl DevelopmentClientOutputV1 {
    pub fn encode(&self) -> Result<Vec<u8>, EncodingError> {
        match self {
            Self::Genesis(value) => value.encode(),
            Self::ProverRequest(value) => value.encode(),
        }
    }
}
