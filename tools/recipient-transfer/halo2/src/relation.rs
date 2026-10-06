use crate::{F, PUBLIC_COUNT};
use ff::{Field, PrimeField};
use shielded_consensus_halo2::tree::native_hash as h;
pub type Statement = [F; PUBLIC_COUNT];
// Public: version,network,asset,mission,root,nullifier,request,from,until,fee,payment,change,binding.
#[derive(Clone, Debug)]
pub struct Witness {
    pub recipient_secret: F,
    pub input_origin: F,
    pub input_value: u64,
    pub input_expiry: u64,
    pub input_secret: F,
    pub input_blind: F,
    pub position: u16,
    pub path: [F; 4],
    pub destination: F,
    pub payment: u64,
    pub payment_expiry: u64,
    pub payment_secret: F,
    pub payment_blind: F,
    pub change: u64,
    pub change_secret: F,
    pub change_blind: F,
}
#[derive(Clone, Debug)]
pub struct Assignment {
    pub public: Statement,
    pub witness: Witness,
}
pub fn integer(f: F) -> Option<u64> {
    let b = f.to_repr();
    if b[8..].iter().any(|x| *x != 0) {
        None
    } else {
        Some(u64::from_le_bytes(b[..8].try_into().ok()?))
    }
}
pub fn network(bootstrap: [u8; 32]) -> F {
    h([
        F::from(820),
        F::from_u128(u128::from_le_bytes(bootstrap[..16].try_into().unwrap())),
        F::from_u128(u128::from_le_bytes(bootstrap[16..].try_into().unwrap())),
    ])
}
pub fn key(secret: F) -> F {
    h([F::from(810), secret])
}
pub fn note(p: &Statement, origin: F, value: u64, expiry: u64, key: F, secret: F, blind: F) -> F {
    h([
        F::from(811),
        p[1],
        p[2],
        p[3],
        origin,
        F::from(expiry),
        F::from(value),
        key,
        secret,
        blind,
    ])
}
pub fn input(a: &Assignment) -> F {
    let w = &a.witness;
    note(
        &a.public,
        w.input_origin,
        w.input_value,
        w.input_expiry,
        key(w.recipient_secret),
        w.input_secret,
        w.input_blind,
    )
}
// Position and request are deliberately absent: a duplicated leaf or competing
// intent must yield the same nullifier for the same consumed note/key.
pub fn nullifier(a: &Assignment) -> F {
    h([
        F::from(814),
        a.public[1],
        a.public[2],
        a.public[3],
        input(a),
        a.witness.recipient_secret,
    ])
}
pub fn origin(a: &Assignment) -> F {
    h([
        F::from(816),
        a.witness.input_origin,
        a.public[5],
        a.public[6],
    ])
}
pub fn leaf(n: F) -> F {
    h([F::from(812), n])
}
pub fn branch(l: F, r: F) -> F {
    h([F::from(813), l, r])
}
pub fn root(n: F, position: u16, path: [F; 4]) -> F {
    let mut v = leaf(n);
    for (i, s) in path.iter().enumerate() {
        v = if (position >> i) & 1 == 0 {
            branch(v, *s)
        } else {
            branch(*s, v)
        }
    }
    v
}
pub fn tree(notes: &[F]) -> Result<(F, Vec<[F; 4]>), &'static str> {
    if notes.is_empty()
        || notes.len() > 16
        || notes.iter().any(|x| *x == F::ZERO)
        || notes
            .iter()
            .enumerate()
            .any(|(i, x)| notes[..i].contains(x))
    {
        return Err("tree-input");
    }
    let mut nodes = vec![leaf(F::ZERO); 16];
    for (i, n) in notes.iter().enumerate() {
        nodes[i] = leaf(*n)
    }
    let mut paths = vec![[F::ZERO; 4]; notes.len()];
    for d in 0..4 {
        for (i, p) in paths.iter_mut().enumerate() {
            p[d] = nodes[(i >> d) ^ 1]
        }
        nodes = nodes.chunks_exact(2).map(|v| branch(v[0], v[1])).collect()
    }
    Ok((nodes[0], paths))
}
pub fn binding(p: &Statement) -> F {
    let mut v = [F::ZERO; 13];
    v[0] = F::from(815);
    v[1..].copy_from_slice(&p[..12]);
    h(v)
}
pub fn derive(a: &mut Assignment) {
    a.public[4] = root(input(a), a.witness.position, a.witness.path);
    a.public[5] = nullifier(a);
    let w = &a.witness;
    let o = origin(a);
    a.public[10] = note(
        &a.public,
        o,
        w.payment,
        w.payment_expiry,
        w.destination,
        w.payment_secret,
        w.payment_blind,
    );
    a.public[11] = note(
        &a.public,
        o,
        w.change,
        w.input_expiry,
        key(w.recipient_secret),
        w.change_secret,
        w.change_blind,
    );
    a.public[12] = binding(&a.public)
}
pub fn validate(a: &Assignment) -> Result<(), &'static str> {
    let p = &a.public;
    let w = &a.witness;
    if p[0] != F::from(8) || p.iter().any(|v| *v == F::ZERO) || p[10] == p[11] {
        return Err("public-domain");
    }
    let from = integer(p[7]).ok_or("from-range")?;
    let until = integer(p[8]).ok_or("until-range")?;
    let fee = integer(p[9]).ok_or("fee-range")?;
    if from == 0
        || from >= until
        || fee == 0
        || w.position >= 16
        || until > w.payment_expiry
        || w.payment_expiry > w.input_expiry
    {
        return Err("window-expiry-position");
    }
    if w.payment
        .checked_add(w.change)
        .and_then(|v| v.checked_add(fee))
        != Some(w.input_value)
        || w.payment == 0
        || w.change == 0
        || w.input_value == 0
    {
        return Err("conservation");
    }
    if [
        w.recipient_secret,
        w.input_origin,
        w.input_secret,
        w.input_blind,
        w.destination,
        w.payment_secret,
        w.payment_blind,
        w.change_secret,
        w.change_blind,
    ]
    .iter()
    .any(|v| *v == F::ZERO)
        || key(w.recipient_secret) == F::ZERO
        || input(a) == F::ZERO
        || origin(a) == F::ZERO
    {
        return Err("opening-zero");
    }
    let mut expected = a.clone();
    derive(&mut expected);
    if p != &expected.public {
        return Err("public-binding");
    }
    Ok(())
}
