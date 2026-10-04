use std::{fs, path::Path};

use crate::{
    constants::{CAPACITY, MAX_PROOF_BYTES, PUBLIC_INPUT_COUNT},
    encoding::{
        Digest32, EncodingError, KatV1, ProfileDescriptorV1, WorkerOpcode, WorkerRequestV1,
        WorkerResponseV1, WorkerStatus,
    },
    field::{decode_field, encode_field, FieldBytes, F},
    profile::validate_pinned_cryptography,
    relation::PublicStatement,
    tree::{append_two, tree_root},
    verifier::{PinnedVerifier, VerifyError},
};

const PROFILE_ARTIFACT_LIMIT: u64 = 4096;
const KAT_ARTIFACT_LIMIT: u64 = (MAX_PROOF_BYTES + 1024) as u64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WorkerFatal {
    Artifact,
    Framing,
    Identity,
    RequestId,
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DispatchResult {
    pub response: WorkerResponseV1,
    pub terminate: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AppendResponseV1 {
    pub root_before: F,
    pub root_after: F,
    pub position_0: u16,
    pub position_1: u16,
}

pub struct WorkerRuntime {
    descriptor: ProfileDescriptorV1,
    descriptor_bytes: Vec<u8>,
    kat: KatV1,
    verifier: PinnedVerifier,
    next_request_id: u64,
}

struct PayloadReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> PayloadReader<'a> {
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
    fn u32(&mut self) -> Result<u32, EncodingError> { Ok(u32::from_le_bytes(self.array()?)) }
    fn field(&mut self) -> Result<F, EncodingError> {
        decode_field(self.array()?).map_err(|_| EncodingError::InvalidField)
    }
    fn fields<const N: usize>(&mut self) -> Result<[FieldBytes; N], EncodingError> {
        let mut result = [[0u8; 32]; N];
        for value in &mut result {
            *value = self.array()?;
            decode_field(*value).map_err(|_| EncodingError::InvalidField)?;
        }
        Ok(result)
    }
    fn finish(self) -> Result<(), EncodingError> {
        if self.offset == self.bytes.len() { Ok(()) } else { Err(EncodingError::TrailingBytes) }
    }
}

fn bounded_read(path: &Path, limit: u64) -> Result<Vec<u8>, WorkerFatal> {
    let metadata = fs::metadata(path).map_err(|_| WorkerFatal::Artifact)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > limit {
        return Err(WorkerFatal::Artifact);
    }
    let bytes = fs::read(path).map_err(|_| WorkerFatal::Artifact)?;
    if bytes.len() as u64 != metadata.len() { return Err(WorkerFatal::Artifact); }
    Ok(bytes)
}

impl WorkerRuntime {
    pub fn from_artifact_files(profile_path: &Path, kat_path: &Path) -> Result<Self, WorkerFatal> {
        let descriptor_bytes = bounded_read(profile_path, PROFILE_ARTIFACT_LIMIT)?;
        let kat_bytes = bounded_read(kat_path, KAT_ARTIFACT_LIMIT)?;
        Self::from_artifact_bytes(&descriptor_bytes, &kat_bytes)
    }

    pub fn from_artifact_bytes(
        descriptor_bytes: &[u8],
        kat_bytes: &[u8],
    ) -> Result<Self, WorkerFatal> {
        if descriptor_bytes.is_empty()
            || descriptor_bytes.len() as u64 > PROFILE_ARTIFACT_LIMIT
            || kat_bytes.is_empty()
            || kat_bytes.len() as u64 > KAT_ARTIFACT_LIMIT
        {
            return Err(WorkerFatal::Artifact);
        }
        let descriptor = ProfileDescriptorV1::decode(descriptor_bytes).map_err(|_| WorkerFatal::Artifact)?;
        let kat = KatV1::decode(kat_bytes).map_err(|_| WorkerFatal::Artifact)?;
        let verifier = PinnedVerifier::new().map_err(|_| WorkerFatal::Internal)?;
        validate_pinned_cryptography(&verifier, &descriptor, &kat)
            .map_err(|_| WorkerFatal::Artifact)?;
        Ok(Self {
            descriptor,
            descriptor_bytes: descriptor_bytes.to_vec(),
            kat,
            verifier,
            next_request_id: 1,
        })
    }

    pub fn profile_id(&self) -> Digest32 { self.descriptor.identity() }
    pub fn descriptor_bytes(&self) -> &[u8] { &self.descriptor_bytes }
    pub fn kat(&self) -> &KatV1 { &self.kat }

    pub fn dispatch(&mut self, request: WorkerRequestV1) -> Result<DispatchResult, WorkerFatal> {
        if request.profile_id != self.profile_id() { return Err(WorkerFatal::Identity); }
        if request.request_id != self.next_request_id { return Err(WorkerFatal::RequestId); }
        self.next_request_id = self.next_request_id.checked_add(1).ok_or(WorkerFatal::RequestId)?;
        let (status, payload, terminate) = match request.opcode {
            WorkerOpcode::Profile => {
                if !request.payload.is_empty() { return Err(WorkerFatal::Framing); }
                (WorkerStatus::Ok, self.descriptor_bytes.clone(), false)
            }
            WorkerOpcode::TreeRootV1 => match decode_tree_root_payload(&request.payload)
                .and_then(|values| tree_root(&values).map_err(|_| EncodingError::InvalidValue))
            {
                Ok(root) => (WorkerStatus::Ok, encode_field(root).to_vec(), false),
                Err(EncodingError::InvalidValue) => (WorkerStatus::InternalFailure, Vec::new(), true),
                Err(_) => return Err(WorkerFatal::Framing),
            },
            WorkerOpcode::VerifyProofV1 => {
                let (public, proof) = decode_verify_proof_payload(
                    &request.payload,
                    self.descriptor.exact_proof_length as usize,
                ).map_err(|_| WorkerFatal::Framing)?;
                match self.verifier.verify_public_bytes(&public, proof) {
                    Ok(()) => (WorkerStatus::Ok, Vec::new(), false),
                    Err(VerifyError::InvalidStatement) => (WorkerStatus::InvalidStatement, Vec::new(), false),
                    Err(VerifyError::InvalidProof) => (WorkerStatus::InvalidProof, Vec::new(), false),
                    Err(VerifyError::InternalFailure) => (WorkerStatus::InternalFailure, Vec::new(), true),
                }
            }
            WorkerOpcode::VerifyAndAppendV1 => {
                let (commitments, public, proof) = decode_verify_append_payload(
                    &request.payload,
                    self.descriptor.exact_proof_length as usize,
                ).map_err(|_| WorkerFatal::Framing)?;
                let root_before = match tree_root(&commitments) {
                    Ok(root) => root,
                    Err(_) => return Ok(self.response(&request, WorkerStatus::InternalFailure, Vec::new(), true)),
                };
                match self.verifier.verify_public_bytes(&public, proof) {
                    Err(VerifyError::InvalidStatement) => (WorkerStatus::InvalidStatement, Vec::new(), false),
                    Err(VerifyError::InvalidProof) => (WorkerStatus::InvalidProof, Vec::new(), false),
                    Err(VerifyError::InternalFailure) => (WorkerStatus::InternalFailure, Vec::new(), true),
                    Ok(()) => {
                        let statement = PublicStatement::from_field_bytes(public)
                            .map_err(|_| WorkerFatal::Framing)?;
                        match append_two(&commitments, statement.0[10], statement.0[11]) {
                            Ok(transition) => {
                                let response = AppendResponseV1 {
                                    root_before,
                                    root_after: transition.root_after,
                                    position_0: transition.position_0,
                                    position_1: transition.position_1,
                                };
                                (WorkerStatus::Ok, encode_append_response(response), false)
                            }
                            Err(_) => (WorkerStatus::InvalidStatement, Vec::new(), false),
                        }
                    }
                }
            }
        };
        Ok(self.response(&request, status, payload, terminate))
    }

    fn response(
        &self,
        request: &WorkerRequestV1,
        status: WorkerStatus,
        payload: Vec<u8>,
        terminate: bool,
    ) -> DispatchResult {
        DispatchResult {
            response: WorkerResponseV1 {
                opcode: request.opcode,
                request_id: request.request_id,
                profile_id: self.profile_id(),
                status,
                payload,
            },
            terminate,
        }
    }
}

pub fn encode_tree_root_payload(commitments: &[F]) -> Result<Vec<u8>, EncodingError> {
    if commitments.len() > CAPACITY { return Err(EncodingError::LimitExceeded); }
    let mut output = Vec::with_capacity(2 + commitments.len() * 32);
    output.extend_from_slice(&(commitments.len() as u16).to_le_bytes());
    for commitment in commitments { output.extend_from_slice(&encode_field(*commitment)); }
    Ok(output)
}

fn decode_tree_root_payload(bytes: &[u8]) -> Result<Vec<F>, EncodingError> {
    let mut reader = PayloadReader::new(bytes);
    let count = usize::from(reader.u16()?);
    if count > CAPACITY { return Err(EncodingError::LimitExceeded); }
    let mut commitments = Vec::with_capacity(count);
    for _ in 0..count { commitments.push(reader.field()?); }
    reader.finish()?;
    Ok(commitments)
}

pub fn encode_verify_proof_payload(
    public: &[FieldBytes; PUBLIC_INPUT_COUNT],
    proof: &[u8],
) -> Result<Vec<u8>, EncodingError> {
    if proof.is_empty() || proof.len() > MAX_PROOF_BYTES { return Err(EncodingError::LimitExceeded); }
    let mut output = Vec::with_capacity(PUBLIC_INPUT_COUNT * 32 + 4 + proof.len());
    for value in public {
        decode_field(*value).map_err(|_| EncodingError::InvalidField)?;
        output.extend_from_slice(value);
    }
    output.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    output.extend_from_slice(proof);
    Ok(output)
}

fn decode_verify_proof_payload(
    bytes: &[u8],
    expected_proof_length: usize,
) -> Result<([FieldBytes; PUBLIC_INPUT_COUNT], &[u8]), EncodingError> {
    let mut reader = PayloadReader::new(bytes);
    let public = reader.fields()?;
    let proof_length = reader.u32()? as usize;
    if proof_length != expected_proof_length || proof_length > MAX_PROOF_BYTES {
        return Err(EncodingError::InvalidLength);
    }
    let proof = reader.take(proof_length)?;
    reader.finish()?;
    Ok((public, proof))
}

pub fn encode_verify_append_payload(
    commitments: &[F],
    public: &[FieldBytes; PUBLIC_INPUT_COUNT],
    proof: &[u8],
) -> Result<Vec<u8>, EncodingError> {
    if commitments.len() > CAPACITY - 2 { return Err(EncodingError::LimitExceeded); }
    let mut output = encode_tree_root_payload(commitments)?;
    output.extend_from_slice(&encode_verify_proof_payload(public, proof)?);
    Ok(output)
}

fn decode_verify_append_payload(
    bytes: &[u8],
    expected_proof_length: usize,
) -> Result<(Vec<F>, [FieldBytes; PUBLIC_INPUT_COUNT], &[u8]), EncodingError> {
    let mut reader = PayloadReader::new(bytes);
    let count = usize::from(reader.u16()?);
    if count > CAPACITY - 2 { return Err(EncodingError::LimitExceeded); }
    let mut commitments = Vec::with_capacity(count);
    for _ in 0..count { commitments.push(reader.field()?); }
    let public = reader.fields()?;
    let proof_length = reader.u32()? as usize;
    if proof_length != expected_proof_length || proof_length > MAX_PROOF_BYTES {
        return Err(EncodingError::InvalidLength);
    }
    let proof = reader.take(proof_length)?;
    reader.finish()?;
    Ok((commitments, public, proof))
}

fn encode_append_response(response: AppendResponseV1) -> Vec<u8> {
    let mut output = Vec::with_capacity(68);
    output.extend_from_slice(&encode_field(response.root_before));
    output.extend_from_slice(&encode_field(response.root_after));
    output.extend_from_slice(&response.position_0.to_le_bytes());
    output.extend_from_slice(&response.position_1.to_le_bytes());
    output
}

pub fn decode_append_response(bytes: &[u8]) -> Result<AppendResponseV1, EncodingError> {
    let mut reader = PayloadReader::new(bytes);
    let response = AppendResponseV1 {
        root_before: reader.field()?,
        root_after: reader.field()?,
        position_0: reader.u16()?,
        position_1: reader.u16()?,
    };
    reader.finish()?;
    Ok(response)
}
