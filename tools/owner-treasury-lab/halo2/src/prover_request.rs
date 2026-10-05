//! Fixed-size private development request. Not authorization or a wallet note format.
use crate::{
    context::network_domain,
    relation::{integer, validate, Assignment, Witness},
    F, PUBLIC_COUNT,
};
use ff::PrimeField;
use sha2::{Digest, Sha256};

pub const MAGIC: &[u8; 8] = b"1SOPRV01";
pub const WITNESS_COUNT: usize = 31;
pub const BYTES: usize = 8 + 4 * 32 + (PUBLIC_COUNT + WITNESS_COUNT) * 32;
pub const PARAMS: &str = "1cb278fe4d9cf5325e5cbc710d863c0deca3e961e1b8f6c8736890c43345c461";
pub const VK: &str = "a02861479050d671419f1e2146410ab3130d3766185898de0140bac4743c17f2";

fn hash_bytes(text: &str) -> [u8; 32] {
    let mut out = [0; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).unwrap();
    }
    out
}
pub fn witness_fields(w: &Witness) -> [F; WITNESS_COUNT] {
    [
        F::from(w.parent_cap),
        F::from(w.parent_spent),
        F::from(w.parent_version),
        w.parent_blind,
        w.parent_next_blind,
        F::from(w.grant_cap),
        F::from(w.grant_spent),
        F::from(w.grant_version),
        w.grant_blind,
        w.grant_next_blind,
        F::from(w.grant_expiry),
        w.agent_secret,
        w.recipient,
        F::from(w.payment),
        w.payment_blind,
        F::from(u64::from(w.input_position)),
        F::from(w.input_value),
        F::from(w.input_expiry),
        w.input_note_secret,
        w.input_blind,
        w.path[0],
        w.path[1],
        w.path[2],
        w.path[3],
        F::from(w.change_value),
        w.change_key,
        F::from(w.change_expiry),
        w.change_note_secret,
        w.change_blind,
        F::from(w.payment_expiry),
        w.payment_note_secret,
    ]
}
pub fn encode(a: &Assignment, bootstrap: [u8; 32]) -> Result<Vec<u8>, &'static str> {
    validate(a)?;
    if a.public[1] != network_domain(bootstrap) {
        return Err("network-domain");
    }
    let mut out = MAGIC.to_vec();
    out.extend(Sha256::digest(include_bytes!("../../PROFILE_V1.json")));
    out.extend(hash_bytes(PARAMS));
    out.extend(hash_bytes(VK));
    out.extend(bootstrap);
    for f in a.public.iter().chain(witness_fields(&a.witness).iter()) {
        out.extend(f.to_repr());
    }
    Ok(out)
}
pub fn decode(raw: &[u8]) -> Result<Assignment, &'static str> {
    let a = syntax(raw)?;
    validate(&a)?;
    Ok(a)
}

// Syntax only for the separate private note controller. This never verifies a
// proof or establishes permission; public request construction validates next.
pub(crate) fn syntax(raw: &[u8]) -> Result<Assignment, &'static str> {
    if raw.len() != BYTES || &raw[..8] != MAGIC {
        return Err("request-bound");
    }
    let expected: [u8; 32] = Sha256::digest(include_bytes!("../../PROFILE_V1.json")).into();
    if raw[8..40] != expected || raw[40..72] != hash_bytes(PARAMS) || raw[72..104] != hash_bytes(VK)
    {
        return Err("profile-pins");
    }
    let bootstrap: [u8; 32] = raw[104..136].try_into().map_err(|_| "bootstrap")?;
    let fields = raw[136..]
        .chunks_exact(32)
        .map(|chunk| Option::<F>::from(F::from_repr(chunk.try_into().unwrap())).ok_or("field"))
        .collect::<Result<Vec<_>, _>>()?;
    let public = fields[..PUBLIC_COUNT]
        .try_into()
        .map_err(|_| "public-count")?;
    let w = &fields[PUBLIC_COUNT..];
    let n = |i| integer(w[i]).ok_or("witness-integer");
    let witness = Witness {
        parent_cap: n(0)?,
        parent_spent: n(1)?,
        parent_version: n(2)?,
        parent_blind: w[3],
        parent_next_blind: w[4],
        grant_cap: n(5)?,
        grant_spent: n(6)?,
        grant_version: n(7)?,
        grant_blind: w[8],
        grant_next_blind: w[9],
        grant_expiry: n(10)?,
        agent_secret: w[11],
        recipient: w[12],
        payment: n(13)?,
        payment_blind: w[14],
        input_position: u16::try_from(n(15)?).map_err(|_| "position")?,
        input_value: n(16)?,
        input_expiry: n(17)?,
        input_note_secret: w[18],
        input_blind: w[19],
        path: w[20..24].try_into().map_err(|_| "path")?,
        change_value: n(24)?,
        change_key: w[25],
        change_expiry: n(26)?,
        change_note_secret: w[27],
        change_blind: w[28],
        payment_expiry: n(29)?,
        payment_note_secret: w[30],
    };
    let a = Assignment { public, witness };
    if a.public[1] != network_domain(bootstrap) {
        return Err("network-domain");
    }
    if a.witness.input_position >= 16 {
        return Err("position");
    }
    Ok(a)
}
