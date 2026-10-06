use crate::{
    relation::{integer, Statement},
    F, PROOF_BYTES, PUBLIC_COUNT,
};
use ff::{Field, PrimeField};
pub const MAGIC: &[u8; 8] = b"1SRCT008";
pub const BYTES: usize = 8 + PUBLIC_COUNT * 32 + PROOF_BYTES;
pub fn encode(p: &Statement, proof: &[u8]) -> Result<Vec<u8>, &'static str> {
    if proof.len() != PROOF_BYTES {
        return Err("proof-size");
    }
    let mut raw = MAGIC.to_vec();
    for f in p {
        raw.extend(f.to_repr())
    }
    raw.extend(proof);
    decode(&raw)?;
    Ok(raw)
}
pub fn decode(raw: &[u8]) -> Result<(Statement, &[u8]), &'static str> {
    if raw.len() != BYTES || &raw[..8] != MAGIC {
        return Err("wire-bound");
    }
    let mut p = [F::ZERO; PUBLIC_COUNT];
    for (f, b) in p
        .iter_mut()
        .zip(raw[8..8 + 32 * PUBLIC_COUNT].chunks_exact(32))
    {
        *f = Option::<F>::from(F::from_repr(b.try_into().unwrap())).ok_or("field")?
    }
    if p[0] != F::from(8)
        || p.iter().any(|f| *f == F::ZERO)
        || [7, 8, 9].iter().any(|i| integer(p[*i]).is_none())
        || integer(p[7]) >= integer(p[8])
        || p[10] == p[11]
    {
        return Err("public-syntax");
    }
    Ok((p, &raw[8 + 32 * PUBLIC_COUNT..]))
}
