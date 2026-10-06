use crate::{
    profile_pins,
    relation::{self as r, Assignment, Witness},
    F, PUBLIC_COUNT, WITNESS_COUNT,
};
use ff::PrimeField;
use sha2::{Digest, Sha256};
pub const MAGIC: &[u8; 8] = b"1SRCP008";
pub const BYTES: usize = 136 + 32 * (PUBLIC_COUNT + WITNESS_COUNT);
pub fn id(s: &str) -> [u8; 32] {
    let mut b = [0; 32];
    for (i, v) in b.iter_mut().enumerate() {
        *v = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("frozen hash")
    }
    b
}
pub fn fields(w: &Witness) -> [F; WITNESS_COUNT] {
    [
        w.recipient_secret,
        w.input_origin,
        F::from(w.input_value),
        F::from(w.input_expiry),
        w.input_secret,
        w.input_blind,
        F::from(w.position as u64),
        w.path[0],
        w.path[1],
        w.path[2],
        w.path[3],
        w.destination,
        F::from(w.payment),
        F::from(w.payment_expiry),
        w.payment_secret,
        w.payment_blind,
        F::from(w.change),
        w.change_secret,
        w.change_blind,
    ]
}
pub fn encode(a: &Assignment, bootstrap: [u8; 32]) -> Result<Vec<u8>, &'static str> {
    r::validate(a)?;
    if a.public[1] != r::network(bootstrap) {
        return Err("network");
    }
    let mut raw = MAGIC.to_vec();
    raw.extend(Sha256::digest(include_bytes!("../../PROFILE_V1.json")));
    raw.extend(id(profile_pins::PARAMS));
    raw.extend(id(profile_pins::VK));
    raw.extend(bootstrap);
    for f in a.public.iter().chain(fields(&a.witness).iter()) {
        raw.extend(f.to_repr())
    }
    Ok(raw)
}
pub fn decode(raw: &[u8]) -> Result<Assignment, &'static str> {
    if raw.len() != BYTES || &raw[..8] != MAGIC {
        return Err("request-bound");
    }
    let expected: [u8; 32] = Sha256::digest(include_bytes!("../../PROFILE_V1.json")).into();
    if raw[8..40] != expected
        || raw[40..72] != id(profile_pins::PARAMS)
        || raw[72..104] != id(profile_pins::VK)
    {
        return Err("pins");
    }
    let bootstrap = raw[104..136].try_into().map_err(|_| "bootstrap")?;
    let fs = raw[136..]
        .chunks_exact(32)
        .map(|b| Option::<F>::from(F::from_repr(b.try_into().unwrap())).ok_or("field"))
        .collect::<Result<Vec<_>, _>>()?;
    let public = fs[..PUBLIC_COUNT].try_into().map_err(|_| "public")?;
    let f = &fs[PUBLIC_COUNT..];
    let n = |i| r::integer(f[i]).ok_or("integer");
    let witness = Witness {
        recipient_secret: f[0],
        input_origin: f[1],
        input_value: n(2)?,
        input_expiry: n(3)?,
        input_secret: f[4],
        input_blind: f[5],
        position: u16::try_from(n(6)?).map_err(|_| "position")?,
        path: f[7..11].try_into().unwrap(),
        destination: f[11],
        payment: n(12)?,
        payment_expiry: n(13)?,
        payment_secret: f[14],
        payment_blind: f[15],
        change: n(16)?,
        change_secret: f[17],
        change_blind: f[18],
    };
    let a = Assignment { public, witness };
    if a.public[1] != r::network(bootstrap) {
        return Err("network");
    }
    r::validate(&a)?;
    Ok(a)
}
