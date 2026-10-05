//! Exact local component envelope. Not a P5 transaction encoding.
use crate::{relation::Statement, F, PROOF_BYTES, PUBLIC_COUNT};
use ff::PrimeField;
pub const MAGIC: [u8; 8] = *b"1STPAY01";
pub const BYTES: usize = 8 + PUBLIC_COUNT * 32 + PROOF_BYTES;
pub fn fields(raw: &[u8]) -> Result<Vec<F>, &'static str> {
    if raw.len() % 32 != 0 || raw.len() > 512 {
        return Err("fields-bound");
    }
    raw.chunks_exact(32)
        .map(|b| Option::<F>::from(F::from_repr(b.try_into().unwrap())).ok_or("noncanonical-field"))
        .collect()
}
pub fn encode(p: &Statement, proof: &[u8]) -> Result<Vec<u8>, &'static str> {
    if proof.len() != PROOF_BYTES {
        return Err("proof-bound");
    }
    let mut out = MAGIC.to_vec();
    for field in p {
        out.extend(field.to_repr());
    }
    out.extend(proof);
    Ok(out)
}
pub fn decode(raw: &[u8]) -> Result<(Statement, &[u8]), &'static str> {
    if raw.len() != BYTES || raw[..8] != MAGIC {
        return Err("envelope-bound-version");
    }
    let mut p = [F::zero(); PUBLIC_COUNT];
    for (f, b) in p
        .iter_mut()
        .zip(raw[8..8 + PUBLIC_COUNT * 32].chunks_exact(32))
    {
        *f = Option::<F>::from(F::from_repr(b.try_into().unwrap())).ok_or("noncanonical-field")?;
    }
    Ok((p, &raw[8 + PUBLIC_COUNT * 32..]))
}
