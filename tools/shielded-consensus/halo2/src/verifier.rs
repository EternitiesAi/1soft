use halo2_proofs::{
    pasta::EqAffine,
    plonk::{keygen_vk, verify_proof, SingleVerifier, VerifyingKey},
    poly::commitment::Params,
    transcript::{Blake2bRead, Challenge255},
};
use sha2::{Digest, Sha256};

use crate::{
    circuit::NoteCircuit,
    constants::K,
    encoding::Digest32,
    field::FieldBytes,
    relation::PublicStatement,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerifyError {
    InvalidStatement,
    InvalidProof,
    InternalFailure,
}

pub struct PinnedVerifier {
    pub(crate) params: Params<EqAffine>,
    pub(crate) vk: VerifyingKey<EqAffine>,
}

impl PinnedVerifier {
    pub fn new() -> Result<Self, VerifyError> {
        let params = Params::new(K);
        let vk = keygen_vk(&params, &NoteCircuit::default())
            .map_err(|_| VerifyError::InternalFailure)?;
        Ok(Self { params, vk })
    }

    pub fn verify(
        &self,
        statement: &PublicStatement,
        proof: &[u8],
    ) -> Result<(), VerifyError> {
        statement
            .validate_shape()
            .map_err(|_| VerifyError::InvalidStatement)?;
        let instances = statement.0;
        let strategy = SingleVerifier::new(&self.params);
        let mut transcript = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(proof);
        verify_proof(
            &self.params,
            &self.vk,
            strategy,
            &[&[&instances]],
            &mut transcript,
        )
        .map_err(|_| VerifyError::InvalidProof)
    }

    pub fn verify_public_bytes(
        &self,
        public_inputs: &[FieldBytes; crate::constants::PUBLIC_INPUT_COUNT],
        proof: &[u8],
    ) -> Result<(), VerifyError> {
        let statement = PublicStatement::from_field_bytes(*public_inputs)
            .map_err(|_| VerifyError::InvalidStatement)?;
        self.verify(&statement, proof)
    }

    pub fn parameter_bytes(&self) -> Result<Vec<u8>, VerifyError> {
        let mut bytes = Vec::new();
        self.params
            .write(&mut bytes)
            .map_err(|_| VerifyError::InternalFailure)?;
        if bytes.is_empty() {
            return Err(VerifyError::InternalFailure);
        }
        Ok(bytes)
    }

    pub fn parameter_hash(&self) -> Result<Digest32, VerifyError> {
        Ok(Sha256::digest(self.parameter_bytes()?).into())
    }

    pub fn verifying_key_bytes(&self) -> Result<Vec<u8>, VerifyError> {
        let bytes = format!("{:?}", self.vk.pinned()).into_bytes();
        if bytes.is_empty() {
            return Err(VerifyError::InternalFailure);
        }
        Ok(bytes)
    }

    pub fn verifying_key_hash(&self) -> Result<Digest32, VerifyError> {
        Ok(Sha256::digest(self.verifying_key_bytes()?).into())
    }
}
