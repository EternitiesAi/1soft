//! Pure P7 opening/path/request derivation. Not proving or spending authority.
use crate::{prover_request, relation, F};
use ff::{Field, PrimeField};

pub fn derive(raw: &[u8]) -> Result<Vec<u8>, &'static str> {
    let end = prover_request::BYTES;
    if raw.len() < end + 2 {
        return Err("note-bound");
    }
    let a = prover_request::syntax(&raw[..end])?;
    let count = usize::from(u16::from_le_bytes(raw[end..end + 2].try_into().unwrap()));
    if count == 0 || count > 16 || raw.len() != end + 2 + count * 32 {
        return Err("notes-bound");
    }
    let notes = crate::wire::fields(&raw[end + 2..])?;
    let w = &a.witness;
    let key = relation::agent_key(w.agent_secret);
    if a.public[0] != F::from(2)
        || [1, 2, 3, 5, 6, 14, 26, 28]
            .iter()
            .any(|i| a.public[*i] == F::ZERO)
        || [14, 26, 28]
            .iter()
            .any(|i| relation::integer(a.public[*i]).is_none())
        || w.agent_secret == F::ZERO
        || w.input_value == 0
        || w.input_expiry == 0
        || w.input_note_secret == F::ZERO
        || w.input_blind == F::ZERO
        || a.public[29] != key
    {
        return Err("note-opening");
    }
    let commitment = relation::input_note(&a);
    let position = usize::from(w.input_position);
    if position >= notes.len()
        || notes[position] != commitment
        || notes.iter().any(|n| *n == F::ZERO)
        || notes
            .iter()
            .enumerate()
            .any(|(i, n)| notes[..i].contains(n))
    {
        return Err("note-membership");
    }
    let (root, paths) = relation::tree(&notes)?;
    let mut out = Vec::with_capacity(256);
    for field in [commitment, key, relation::value_nullifier(&a), root]
        .iter()
        .chain(paths[position].iter())
    {
        out.extend(field.to_repr());
    }
    Ok(out)
}

pub fn construct(raw: &[u8]) -> Result<Vec<u8>, &'static str> {
    let mut a = prover_request::syntax(raw)?;
    if [9, 10, 11, 12, 13, 19, 21, 22, 23, 24]
        .iter()
        .any(|i| a.public[*i] != F::ZERO)
    {
        return Err("derived-slots-must-be-empty");
    }
    let pinned = [a.public[7], a.public[8], a.public[20]];
    relation::derived(&mut a);
    if pinned != [a.public[7], a.public[8], a.public[20]] {
        return Err("current-opening-root-differs");
    }
    let bootstrap = raw[104..136].try_into().map_err(|_| "bootstrap")?;
    prover_request::encode(&a, bootstrap)
}
