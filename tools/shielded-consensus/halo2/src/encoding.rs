use std::fmt;

use sha2::{Digest, Sha256};

use crate::{
    constants::{
        BACKEND_ID, CAPACITY, CIRCUIT_ID, DEPLOYMENT_BINDING_VERSION, DEPLOYMENT_DOMAIN,
        DEPLOYMENT_MAGIC, DEPTH, K, KAT_DOMAIN, KAT_MAGIC, MAX_PROOF_BYTES,
        MAX_TRANSACTION_BYTES, MAX_WORKER_FRAME_BYTES, PROFILE_DESCRIPTOR_VERSION,
        PROFILE_DOMAIN, PROFILE_MAGIC, PROVER_REQUEST_BYTES, PROVER_REQUEST_MAGIC,
        PROVER_REQUEST_VERSION, PUBLIC_INPUT_COUNT, RELATION_VERSION, TRANSACTION_MAGIC, TRANSACTION_PREFIX_BYTES, TRANSACTION_WIRE_VERSION, TXID_DOMAIN,
        WITNESS_BYTES, WITNESS_MAGIC, WITNESS_VERSION, WORKER_PROTOCOL_VERSION,
        WORKER_REQUEST_MAGIC, WORKER_RESPONSE_MAGIC,
    },
    field::{decode_field, encode_field, FieldBytes, F},
};

pub type Digest32 = [u8; 32];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EncodingError {
    Truncated,
    TrailingBytes,
    WrongMagic,
    WrongVersion,
    WrongBackend,
    WrongRelation,
    WrongCircuit,
    InvalidAscii,
    InvalidLength,
    InvalidField,
    InvalidValue,
    LimitExceeded,
}

impl fmt::Display for EncodingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Truncated => "truncated binary document",
            Self::TrailingBytes => "trailing bytes",
            Self::WrongMagic => "wrong binary magic",
            Self::WrongVersion => "wrong version",
            Self::WrongBackend => "wrong backend",
            Self::WrongRelation => "wrong relation",
            Self::WrongCircuit => "wrong circuit",
            Self::InvalidAscii => "invalid ASCII string",
            Self::InvalidLength => "invalid length",
            Self::InvalidField => "invalid canonical field",
            Self::InvalidValue => "invalid value",
            Self::LimitExceeded => "protocol hard limit exceeded",
        })
    }
}

impl std::error::Error for EncodingError {}

fn domain_hash(domain: &[u8], bytes: &[u8]) -> Digest32 {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    hasher.finalize().into()
}

fn checked_field(bytes: FieldBytes) -> Result<FieldBytes, EncodingError> {
    decode_field(bytes).map_err(|_| EncodingError::InvalidField)?;
    Ok(bytes)
}

fn checked_fields<const N: usize>(
    fields: [FieldBytes; N],
) -> Result<[FieldBytes; N], EncodingError> {
    for field in fields {
        checked_field(field)?;
    }
    Ok(fields)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], EncodingError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(EncodingError::InvalidLength)?;
        if end > self.bytes.len() {
            return Err(EncodingError::Truncated);
        }
        let value = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], EncodingError> {
        self.take(N)?
            .try_into()
            .map_err(|_| EncodingError::Truncated)
    }

    fn u8(&mut self) -> Result<u8, EncodingError> {
        Ok(self.array::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, EncodingError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, EncodingError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, EncodingError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn finish(self) -> Result<(), EncodingError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(EncodingError::TrailingBytes)
        }
    }
}

fn push_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(output: &mut Vec<u8>, value: u64) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn read_magic(reader: &mut Reader<'_>, expected: [u8; 8]) -> Result<(), EncodingError> {
    if reader.array::<8>()? == expected {
        Ok(())
    } else {
        Err(EncodingError::WrongMagic)
    }
}

fn read_ascii(reader: &mut Reader<'_>) -> Result<String, EncodingError> {
    let length = usize::from(reader.u16()?);
    let bytes = reader.take(length)?;
    if bytes.is_empty() || !bytes.is_ascii() || bytes.contains(&0) {
        return Err(EncodingError::InvalidAscii);
    }
    String::from_utf8(bytes.to_vec()).map_err(|_| EncodingError::InvalidAscii)
}

fn push_ascii(output: &mut Vec<u8>, value: &str) -> Result<(), EncodingError> {
    if value.is_empty() || !value.is_ascii() || value.as_bytes().contains(&0) {
        return Err(EncodingError::InvalidAscii);
    }
    push_u16(
        output,
        u16::try_from(value.len()).map_err(|_| EncodingError::InvalidLength)?,
    );
    output.extend_from_slice(value.as_bytes());
    Ok(())
}

fn read_field(reader: &mut Reader<'_>) -> Result<FieldBytes, EncodingError> {
    checked_field(reader.array()?)
}

fn read_fields<const N: usize>(
    reader: &mut Reader<'_>,
) -> Result<[FieldBytes; N], EncodingError> {
    let mut values = [[0u8; 32]; N];
    for value in &mut values {
        *value = read_field(reader)?;
    }
    Ok(values)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProfileDescriptorV1 {
    pub exact_proof_length: u32,
    pub parameter_hash: Digest32,
    pub verifying_key_hash: Digest32,
    pub circuit_source_hash: Digest32,
    pub cargo_lock_hash: Digest32,
    pub profile_manifest_hash: Digest32,
    pub public_schema_hash: Digest32,
    pub kat_hash: Digest32,
    pub curve_commitment_hash: Digest32,
    pub transcript_poseidon_hash: Digest32,
}

impl ProfileDescriptorV1 {
    pub fn encode(&self) -> Result<Vec<u8>, EncodingError> {
        if self.exact_proof_length == 0 || self.exact_proof_length as usize > MAX_PROOF_BYTES {
            return Err(EncodingError::LimitExceeded);
        }
        let mut output = Vec::with_capacity(384);
        output.extend_from_slice(&PROFILE_MAGIC);
        push_u16(&mut output, PROFILE_DESCRIPTOR_VERSION);
        push_u16(&mut output, BACKEND_ID);
        push_u32(&mut output, RELATION_VERSION);
        push_u16(&mut output, K as u16);
        push_u16(&mut output, DEPTH as u16);
        push_u16(&mut output, PUBLIC_INPUT_COUNT as u16);
        push_u32(&mut output, self.exact_proof_length);
        push_ascii(&mut output, CIRCUIT_ID)?;
        for hash in [
            self.parameter_hash,
            self.verifying_key_hash,
            self.circuit_source_hash,
            self.cargo_lock_hash,
            self.profile_manifest_hash,
            self.public_schema_hash,
            self.kat_hash,
            self.curve_commitment_hash,
            self.transcript_poseidon_hash,
        ] {
            output.extend_from_slice(&hash);
        }
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EncodingError> {
        let mut reader = Reader::new(bytes);
        read_magic(&mut reader, PROFILE_MAGIC)?;
        if reader.u16()? != PROFILE_DESCRIPTOR_VERSION {
            return Err(EncodingError::WrongVersion);
        }
        if reader.u16()? != BACKEND_ID {
            return Err(EncodingError::WrongBackend);
        }
        if reader.u32()? != RELATION_VERSION {
            return Err(EncodingError::WrongRelation);
        }
        if u32::from(reader.u16()?) != K
            || usize::from(reader.u16()?) != DEPTH
            || usize::from(reader.u16()?) != PUBLIC_INPUT_COUNT
        {
            return Err(EncodingError::InvalidValue);
        }
        let exact_proof_length = reader.u32()?;
        if exact_proof_length == 0 || exact_proof_length as usize > MAX_PROOF_BYTES {
            return Err(EncodingError::LimitExceeded);
        }
        if read_ascii(&mut reader)? != CIRCUIT_ID {
            return Err(EncodingError::WrongCircuit);
        }
        let result = Self {
            exact_proof_length,
            parameter_hash: reader.array()?,
            verifying_key_hash: reader.array()?,
            circuit_source_hash: reader.array()?,
            cargo_lock_hash: reader.array()?,
            profile_manifest_hash: reader.array()?,
            public_schema_hash: reader.array()?,
            kat_hash: reader.array()?,
            curve_commitment_hash: reader.array()?,
            transcript_poseidon_hash: reader.array()?,
        };
        reader.finish()?;
        Ok(result)
    }

    pub fn identity(&self) -> Digest32 {
        domain_hash(PROFILE_DOMAIN, &self.encode().expect("validated profile descriptor"))
    }

    pub fn test_fixture() -> Self {
        Self {
            exact_proof_length: 32,
            parameter_hash: [1; 32],
            verifying_key_hash: [2; 32],
            circuit_source_hash: [3; 32],
            cargo_lock_hash: [4; 32],
            profile_manifest_hash: [5; 32],
            public_schema_hash: [6; 32],
            kat_hash: [7; 32],
            curve_commitment_hash: [8; 32],
            transcript_poseidon_hash: [9; 32],
        }
    }

    pub fn decode_test(bytes: &[u8]) -> bool {
        Self::decode(bytes).is_ok()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeploymentBindingV1 {
    pub profile_id: Digest32,
    pub worker_binary_hash: Digest32,
    pub toolchain_manifest_hash: Digest32,
    pub sandbox_policy_hash: Digest32,
}

impl DeploymentBindingV1 {
    pub fn encode(&self) -> Result<Vec<u8>, EncodingError> {
        let mut output = Vec::with_capacity(140);
        output.extend_from_slice(&DEPLOYMENT_MAGIC);
        push_u16(&mut output, DEPLOYMENT_BINDING_VERSION);
        push_u16(&mut output, WORKER_PROTOCOL_VERSION);
        output.extend_from_slice(&self.profile_id);
        output.extend_from_slice(&self.worker_binary_hash);
        output.extend_from_slice(&self.toolchain_manifest_hash);
        output.extend_from_slice(&self.sandbox_policy_hash);
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EncodingError> {
        let mut reader = Reader::new(bytes);
        read_magic(&mut reader, DEPLOYMENT_MAGIC)?;
        if reader.u16()? != DEPLOYMENT_BINDING_VERSION
            || reader.u16()? != WORKER_PROTOCOL_VERSION
        {
            return Err(EncodingError::WrongVersion);
        }
        let result = Self {
            profile_id: reader.array()?,
            worker_binary_hash: reader.array()?,
            toolchain_manifest_hash: reader.array()?,
            sandbox_policy_hash: reader.array()?,
        };
        reader.finish()?;
        Ok(result)
    }

    pub fn identity(&self) -> Digest32 {
        domain_hash(DEPLOYMENT_DOMAIN, &self.encode().expect("validated deployment binding"))
    }

    pub fn test_fixture(profile_id: Digest32) -> Self {
        Self {
            profile_id,
            worker_binary_hash: [10; 32],
            toolchain_manifest_hash: [11; 32],
            sandbox_policy_hash: [12; 32],
        }
    }

    pub fn decode_test(bytes: &[u8]) -> bool {
        Self::decode(bytes).is_ok()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KatV1 {
    pub public_inputs: [FieldBytes; PUBLIC_INPUT_COUNT],
    pub proof: Vec<u8>,
    pub expected_status: u8,
    pub mutation_offset: u32,
    pub xor_mask: u8,
}

impl KatV1 {
    pub fn encode(&self) -> Result<Vec<u8>, EncodingError> {
        checked_fields(self.public_inputs)?;
        if self.proof.is_empty() || self.proof.len() > MAX_PROOF_BYTES {
            return Err(EncodingError::LimitExceeded);
        }
        if self.expected_status != 0
            || self.xor_mask == 0
            || self.mutation_offset as usize >= self.proof.len()
        {
            return Err(EncodingError::InvalidValue);
        }
        let mut output = Vec::with_capacity(468 + self.proof.len());
        output.extend_from_slice(&KAT_MAGIC);
        push_u16(&mut output, 1);
        for field in self.public_inputs {
            output.extend_from_slice(&field);
        }
        push_u32(&mut output, self.proof.len() as u32);
        output.extend_from_slice(&self.proof);
        output.push(self.expected_status);
        push_u32(&mut output, self.mutation_offset);
        output.push(self.xor_mask);
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EncodingError> {
        let mut reader = Reader::new(bytes);
        read_magic(&mut reader, KAT_MAGIC)?;
        if reader.u16()? != 1 {
            return Err(EncodingError::WrongVersion);
        }
        let public_inputs = read_fields(&mut reader)?;
        let proof_length = reader.u32()? as usize;
        if proof_length == 0 || proof_length > MAX_PROOF_BYTES {
            return Err(EncodingError::LimitExceeded);
        }
        let proof = reader.take(proof_length)?.to_vec();
        let expected_status = reader.u8()?;
        let mutation_offset = reader.u32()?;
        let xor_mask = reader.u8()?;
        reader.finish()?;
        let result = Self {
            public_inputs,
            proof,
            expected_status,
            mutation_offset,
            xor_mask,
        };
        result.encode()?;
        Ok(result)
    }

    pub fn identity_hash(&self) -> Digest32 {
        domain_hash(KAT_DOMAIN, &self.encode().expect("validated KAT"))
    }

    pub fn test_fixture() -> Self {
        Self {
            public_inputs: std::array::from_fn(|index| encode_field(F::from(index as u64 + 1))),
            proof: vec![0x5a; 32],
            expected_status: 0,
            mutation_offset: 16,
            xor_mask: 1,
        }
    }

    pub fn decode_test(bytes: &[u8]) -> bool {
        Self::decode(bytes).is_ok()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionV1 {
    pub genesis_sha256: Digest32,
    pub deployment_id: Digest32,
    pub public_inputs: [FieldBytes; PUBLIC_INPUT_COUNT],
    pub proof: Vec<u8>,
}

impl TransactionV1 {
    pub fn encode(&self) -> Result<Vec<u8>, EncodingError> {
        checked_fields(self.public_inputs)?;
        if self.proof.is_empty() || self.proof.len() > MAX_PROOF_BYTES {
            return Err(EncodingError::LimitExceeded);
        }
        let total = TRANSACTION_PREFIX_BYTES
            .checked_add(self.proof.len())
            .ok_or(EncodingError::InvalidLength)?;
        if total > MAX_TRANSACTION_BYTES {
            return Err(EncodingError::LimitExceeded);
        }
        let mut output = Vec::with_capacity(total);
        output.extend_from_slice(&TRANSACTION_MAGIC);
        push_u16(&mut output, TRANSACTION_WIRE_VERSION);
        push_u16(&mut output, BACKEND_ID);
        push_u32(&mut output, RELATION_VERSION);
        output.extend_from_slice(&self.genesis_sha256);
        output.extend_from_slice(&self.deployment_id);
        push_u16(&mut output, PUBLIC_INPUT_COUNT as u16);
        for field in self.public_inputs {
            output.extend_from_slice(&field);
        }
        push_u32(&mut output, self.proof.len() as u32);
        output.extend_from_slice(&self.proof);
        debug_assert_eq!(output.len(), total);
        Ok(output)
    }

    pub fn decode(
        bytes: &[u8],
        expected_proof_length: usize,
        max_transaction_bytes: usize,
    ) -> Result<Self, EncodingError> {
        if bytes.len() > MAX_TRANSACTION_BYTES || bytes.len() > max_transaction_bytes {
            return Err(EncodingError::LimitExceeded);
        }
        let mut reader = Reader::new(bytes);
        read_magic(&mut reader, TRANSACTION_MAGIC)?;
        if reader.u16()? != TRANSACTION_WIRE_VERSION {
            return Err(EncodingError::WrongVersion);
        }
        if reader.u16()? != BACKEND_ID {
            return Err(EncodingError::WrongBackend);
        }
        if reader.u32()? != RELATION_VERSION {
            return Err(EncodingError::WrongRelation);
        }
        let genesis_sha256 = reader.array()?;
        let deployment_id = reader.array()?;
        if usize::from(reader.u16()?) != PUBLIC_INPUT_COUNT {
            return Err(EncodingError::InvalidLength);
        }
        let public_inputs = read_fields(&mut reader)?;
        let proof_length = reader.u32()? as usize;
        if proof_length != expected_proof_length || proof_length > MAX_PROOF_BYTES {
            return Err(EncodingError::InvalidLength);
        }
        let proof = reader.take(proof_length)?.to_vec();
        reader.finish()?;
        Ok(Self {
            genesis_sha256,
            deployment_id,
            public_inputs,
            proof,
        })
    }

    pub fn transaction_id(&self) -> Digest32 {
        domain_hash(TXID_DOMAIN, &self.encode().expect("validated transaction"))
    }

    pub fn test_fixture(proof_length: usize) -> Self {
        Self {
            genesis_sha256: [13; 32],
            deployment_id: [14; 32],
            public_inputs: std::array::from_fn(|index| encode_field(F::from(index as u64 + 1))),
            proof: vec![0x33; proof_length],
        }
    }

    pub fn decode_test(bytes: &[u8]) -> bool {
        if bytes.len() < TRANSACTION_PREFIX_BYTES {
            return false;
        }
        let offset = TRANSACTION_PREFIX_BYTES - 4;
        let claimed = match bytes.get(offset..offset + 4) {
            Some(value) => u32::from_le_bytes(value.try_into().expect("length slice")) as usize,
            None => return false,
        };
        Self::decode(bytes, claimed, MAX_TRANSACTION_BYTES).is_ok()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WitnessV1 {
    pub input_position: u16,
    pub input_value: u64,
    pub input_expiry: u64,
    pub input_blinding: FieldBytes,
    pub spend_secret: FieldBytes,
    pub note_secret: FieldBytes,
    pub authentication_path: [FieldBytes; DEPTH],
    pub output_values: [u64; 2],
    pub output_expiries: [u64; 2],
    pub output_recipient_keys: [FieldBytes; 2],
    pub output_note_secrets: [FieldBytes; 2],
    pub output_blindings: [FieldBytes; 2],
}

impl WitnessV1 {
    pub fn encode(&self) -> Result<Vec<u8>, EncodingError> {
        if usize::from(self.input_position) >= CAPACITY {
            return Err(EncodingError::InvalidValue);
        }
        for field in [
            self.input_blinding,
            self.spend_secret,
            self.note_secret,
            self.authentication_path[0],
            self.authentication_path[1],
            self.authentication_path[2],
            self.authentication_path[3],
            self.output_recipient_keys[0],
            self.output_recipient_keys[1],
            self.output_note_secrets[0],
            self.output_note_secrets[1],
            self.output_blindings[0],
            self.output_blindings[1],
        ] {
            checked_field(field)?;
        }
        let mut output = Vec::with_capacity(WITNESS_BYTES);
        output.extend_from_slice(&WITNESS_MAGIC);
        push_u16(&mut output, WITNESS_VERSION);
        push_u32(&mut output, RELATION_VERSION);
        push_u16(&mut output, self.input_position);
        push_u64(&mut output, self.input_value);
        push_u64(&mut output, self.input_expiry);
        output.extend_from_slice(&self.input_blinding);
        output.extend_from_slice(&self.spend_secret);
        output.extend_from_slice(&self.note_secret);
        for field in self.authentication_path {
            output.extend_from_slice(&field);
        }
        for value in self.output_values {
            push_u64(&mut output, value);
        }
        for expiry in self.output_expiries {
            push_u64(&mut output, expiry);
        }
        for field in self.output_recipient_keys {
            output.extend_from_slice(&field);
        }
        for field in self.output_note_secrets {
            output.extend_from_slice(&field);
        }
        for field in self.output_blindings {
            output.extend_from_slice(&field);
        }
        debug_assert_eq!(output.len(), WITNESS_BYTES);
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EncodingError> {
        if bytes.len() != WITNESS_BYTES {
            return Err(EncodingError::InvalidLength);
        }
        let mut reader = Reader::new(bytes);
        read_magic(&mut reader, WITNESS_MAGIC)?;
        if reader.u16()? != WITNESS_VERSION {
            return Err(EncodingError::WrongVersion);
        }
        if reader.u32()? != RELATION_VERSION {
            return Err(EncodingError::WrongRelation);
        }
        let input_position = reader.u16()?;
        if usize::from(input_position) >= CAPACITY {
            return Err(EncodingError::InvalidValue);
        }
        let input_value = reader.u64()?;
        let input_expiry = reader.u64()?;
        let input_blinding = read_field(&mut reader)?;
        let spend_secret = read_field(&mut reader)?;
        let note_secret = read_field(&mut reader)?;
        let authentication_path = read_fields(&mut reader)?;
        let output_values = [reader.u64()?, reader.u64()?];
        let output_expiries = [reader.u64()?, reader.u64()?];
        let output_recipient_keys = read_fields(&mut reader)?;
        let output_note_secrets = read_fields(&mut reader)?;
        let output_blindings = read_fields(&mut reader)?;
        reader.finish()?;
        Ok(Self {
            input_position,
            input_value,
            input_expiry,
            input_blinding,
            spend_secret,
            note_secret,
            authentication_path,
            output_values,
            output_expiries,
            output_recipient_keys,
            output_note_secrets,
            output_blindings,
        })
    }

    pub fn test_fixture() -> Self {
        let field = |value| encode_field(F::from(value));
        Self {
            input_position: 5,
            input_value: 100,
            input_expiry: 300,
            input_blinding: field(21),
            spend_secret: field(22),
            note_secret: field(23),
            authentication_path: [field(31), field(32), field(33), field(34)],
            output_values: [40, 59],
            output_expiries: [400, 500],
            output_recipient_keys: [field(35), field(36)],
            output_note_secrets: [field(37), field(38)],
            output_blindings: [field(39), field(40)],
        }
    }

    pub fn decode_test(bytes: &[u8]) -> bool {
        Self::decode(bytes).is_ok()
    }
}


#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProverRequestV1 {
    pub genesis_sha256: Digest32,
    pub deployment_id: Digest32,
    pub public_inputs: [FieldBytes; PUBLIC_INPUT_COUNT],
    pub witness: WitnessV1,
}

impl ProverRequestV1 {
    pub fn encode(&self) -> Result<Vec<u8>, EncodingError> {
        checked_fields(self.public_inputs)?;
        let witness = self.witness.encode()?;
        let mut output = Vec::with_capacity(PROVER_REQUEST_BYTES);
        output.extend_from_slice(&PROVER_REQUEST_MAGIC);
        push_u16(&mut output, PROVER_REQUEST_VERSION);
        push_u16(&mut output, BACKEND_ID);
        push_u32(&mut output, RELATION_VERSION);
        output.extend_from_slice(&self.genesis_sha256);
        output.extend_from_slice(&self.deployment_id);
        push_u16(&mut output, PUBLIC_INPUT_COUNT as u16);
        for field in self.public_inputs {
            output.extend_from_slice(&field);
        }
        output.extend_from_slice(&witness);
        debug_assert_eq!(output.len(), PROVER_REQUEST_BYTES);
        Ok(output)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, EncodingError> {
        if bytes.len() != PROVER_REQUEST_BYTES {
            return Err(EncodingError::InvalidLength);
        }
        let mut reader = Reader::new(bytes);
        read_magic(&mut reader, PROVER_REQUEST_MAGIC)?;
        if reader.u16()? != PROVER_REQUEST_VERSION {
            return Err(EncodingError::WrongVersion);
        }
        if reader.u16()? != BACKEND_ID {
            return Err(EncodingError::WrongBackend);
        }
        if reader.u32()? != RELATION_VERSION {
            return Err(EncodingError::WrongRelation);
        }
        let genesis_sha256 = reader.array()?;
        let deployment_id = reader.array()?;
        if usize::from(reader.u16()?) != PUBLIC_INPUT_COUNT {
            return Err(EncodingError::InvalidLength);
        }
        let public_inputs = read_fields(&mut reader)?;
        let witness = WitnessV1::decode(reader.take(WITNESS_BYTES)?)?;
        reader.finish()?;
        Ok(Self {
            genesis_sha256,
            deployment_id,
            public_inputs,
            witness,
        })
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerOpcode {
    Profile = 1,
    TreeRootV1 = 2,
    VerifyAndAppendV1 = 3,
    VerifyProofV1 = 4,
}

impl TryFrom<u16> for WorkerOpcode {
    type Error = EncodingError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::Profile),
            2 => Ok(Self::TreeRootV1),
            3 => Ok(Self::VerifyAndAppendV1),
            4 => Ok(Self::VerifyProofV1),
            _ => Err(EncodingError::InvalidValue),
        }
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerStatus {
    Ok = 0,
    InvalidStatement = 1,
    InvalidProof = 2,
    InternalFailure = 65535,
}

impl TryFrom<u16> for WorkerStatus {
    type Error = EncodingError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Ok),
            1 => Ok(Self::InvalidStatement),
            2 => Ok(Self::InvalidProof),
            65535 => Ok(Self::InternalFailure),
            _ => Err(EncodingError::InvalidValue),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerRequestV1 {
    pub opcode: WorkerOpcode,
    pub request_id: u64,
    pub profile_id: Digest32,
    pub payload: Vec<u8>,
}

impl WorkerRequestV1 {
    fn encode_body(&self) -> Result<Vec<u8>, EncodingError> {
        if self.request_id == 0 {
            return Err(EncodingError::InvalidValue);
        }
        let mut output = Vec::with_capacity(56 + self.payload.len());
        output.extend_from_slice(&WORKER_REQUEST_MAGIC);
        push_u16(&mut output, WORKER_PROTOCOL_VERSION);
        push_u16(&mut output, self.opcode as u16);
        push_u64(&mut output, self.request_id);
        output.extend_from_slice(&self.profile_id);
        push_u32(&mut output, self.payload.len() as u32);
        output.extend_from_slice(&self.payload);
        if output.len() > MAX_WORKER_FRAME_BYTES {
            return Err(EncodingError::LimitExceeded);
        }
        Ok(output)
    }

    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodingError> {
        encode_frame(&self.encode_body()?)
    }

    pub fn decode_frame(bytes: &[u8]) -> Result<Self, EncodingError> {
        let body = decode_frame(bytes)?;
        let mut reader = Reader::new(body);
        read_magic(&mut reader, WORKER_REQUEST_MAGIC)?;
        if reader.u16()? != WORKER_PROTOCOL_VERSION {
            return Err(EncodingError::WrongVersion);
        }
        let opcode = WorkerOpcode::try_from(reader.u16()?)?;
        let request_id = reader.u64()?;
        if request_id == 0 {
            return Err(EncodingError::InvalidValue);
        }
        let profile_id = reader.array()?;
        let payload_length = reader.u32()? as usize;
        let payload = reader.take(payload_length)?.to_vec();
        reader.finish()?;
        Ok(Self {
            opcode,
            request_id,
            profile_id,
            payload,
        })
    }

    pub fn test_fixture(profile_id: Digest32) -> Self {
        Self {
            opcode: WorkerOpcode::Profile,
            request_id: 1,
            profile_id,
            payload: Vec::new(),
        }
    }

    pub fn decode_test(bytes: &[u8]) -> bool {
        Self::decode_frame(bytes).is_ok()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkerResponseV1 {
    pub opcode: WorkerOpcode,
    pub request_id: u64,
    pub profile_id: Digest32,
    pub status: WorkerStatus,
    pub payload: Vec<u8>,
}

impl WorkerResponseV1 {
    fn encode_body(&self) -> Result<Vec<u8>, EncodingError> {
        if self.request_id == 0 {
            return Err(EncodingError::InvalidValue);
        }
        let mut output = Vec::with_capacity(58 + self.payload.len());
        output.extend_from_slice(&WORKER_RESPONSE_MAGIC);
        push_u16(&mut output, WORKER_PROTOCOL_VERSION);
        push_u16(&mut output, self.opcode as u16);
        push_u64(&mut output, self.request_id);
        output.extend_from_slice(&self.profile_id);
        push_u16(&mut output, self.status as u16);
        push_u32(&mut output, self.payload.len() as u32);
        output.extend_from_slice(&self.payload);
        if output.len() > MAX_WORKER_FRAME_BYTES {
            return Err(EncodingError::LimitExceeded);
        }
        Ok(output)
    }

    pub fn encode_frame(&self) -> Result<Vec<u8>, EncodingError> {
        encode_frame(&self.encode_body()?)
    }

    pub fn decode_frame(bytes: &[u8]) -> Result<Self, EncodingError> {
        let body = decode_frame(bytes)?;
        let mut reader = Reader::new(body);
        read_magic(&mut reader, WORKER_RESPONSE_MAGIC)?;
        if reader.u16()? != WORKER_PROTOCOL_VERSION {
            return Err(EncodingError::WrongVersion);
        }
        let opcode = WorkerOpcode::try_from(reader.u16()?)?;
        let request_id = reader.u64()?;
        if request_id == 0 {
            return Err(EncodingError::InvalidValue);
        }
        let profile_id = reader.array()?;
        let status = WorkerStatus::try_from(reader.u16()?)?;
        let payload_length = reader.u32()? as usize;
        let payload = reader.take(payload_length)?.to_vec();
        reader.finish()?;
        Ok(Self {
            opcode,
            request_id,
            profile_id,
            status,
            payload,
        })
    }

    pub fn test_fixture(profile_id: Digest32) -> Self {
        Self {
            opcode: WorkerOpcode::Profile,
            request_id: 1,
            profile_id,
            status: WorkerStatus::Ok,
            payload: Vec::new(),
        }
    }

    pub fn decode_test(bytes: &[u8]) -> bool {
        Self::decode_frame(bytes).is_ok()
    }
}

fn encode_frame(body: &[u8]) -> Result<Vec<u8>, EncodingError> {
    if body.len() > MAX_WORKER_FRAME_BYTES {
        return Err(EncodingError::LimitExceeded);
    }
    let mut output = Vec::with_capacity(4 + body.len());
    push_u32(&mut output, body.len() as u32);
    output.extend_from_slice(body);
    Ok(output)
}

fn decode_frame(bytes: &[u8]) -> Result<&[u8], EncodingError> {
    if bytes.len() < 4 {
        return Err(EncodingError::Truncated);
    }
    let length = u32::from_le_bytes(bytes[..4].try_into().expect("length prefix")) as usize;
    if length > MAX_WORKER_FRAME_BYTES {
        return Err(EncodingError::LimitExceeded);
    }
    if bytes.len() != 4 + length {
        return if bytes.len() < 4 + length {
            Err(EncodingError::Truncated)
        } else {
            Err(EncodingError::TrailingBytes)
        };
    }
    Ok(&bytes[4..])
}
