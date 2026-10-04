use std::fmt;

use ff::{FromUniformBytes, PrimeField};
use pasta_curves::pallas;
use sha2::{Digest, Sha512};

use crate::constants::FIELD_DOMAIN;

pub type F = pallas::Base;
pub type FieldBytes = [u8; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldError {
    NonCanonical,
    EmptyLabel,
    LabelTooLong,
    PayloadTooLong,
    NonAsciiLabel,
    NulLabel,
}

impl fmt::Display for FieldError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NonCanonical => "noncanonical Pallas field encoding",
            Self::EmptyLabel => "empty H2F label",
            Self::LabelTooLong => "H2F label exceeds u16",
            Self::PayloadTooLong => "H2F payload exceeds u32",
            Self::NonAsciiLabel => "H2F label is not ASCII",
            Self::NulLabel => "H2F label contains NUL",
        })
    }
}

impl std::error::Error for FieldError {}

pub fn decode_field(bytes: FieldBytes) -> Result<F, FieldError> {
    let decoded = F::from_repr(bytes);
    Option::<F>::from(decoded).ok_or(FieldError::NonCanonical)
}

pub fn encode_field(value: F) -> FieldBytes {
    value.to_repr()
}

pub fn h2f(label: &[u8], payload: &[u8]) -> Result<F, FieldError> {
    if label.is_empty() {
        return Err(FieldError::EmptyLabel);
    }
    let label_length = u16::try_from(label.len()).map_err(|_| FieldError::LabelTooLong)?;
    let payload_length = u32::try_from(payload.len()).map_err(|_| FieldError::PayloadTooLong)?;
    if !label.is_ascii() {
        return Err(FieldError::NonAsciiLabel);
    }
    if label.contains(&0) {
        return Err(FieldError::NulLabel);
    }

    let mut hasher = Sha512::new();
    hasher.update(FIELD_DOMAIN);
    hasher.update(label_length.to_le_bytes());
    hasher.update(label);
    hasher.update(payload_length.to_le_bytes());
    hasher.update(payload);
    let digest: [u8; 64] = hasher.finalize().into();
    Ok(F::from_uniform_bytes(&digest))
}
