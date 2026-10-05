use crate::{F, PUBLIC_COUNT};
use ff::{Field, PrimeField};
use shielded_consensus_halo2::tree::native_hash as hash;

// Ordered public fields: version, genesis, asset, mission, current-root, parent-id,
// grant-id, parent-old, grant-old, parent-new, grant-new, parent-nullifier,
// grant-nullifier, payment-commitment, epoch, from, until, fee, request, authorization.
pub type Statement = [F; PUBLIC_COUNT];

#[derive(Clone, Debug)]
pub struct Witness {
    pub parent_cap: u64,
    pub parent_spent: u64,
    pub parent_version: u64,
    pub parent_blind: F,
    pub parent_next_blind: F,
    pub grant_cap: u64,
    pub grant_spent: u64,
    pub grant_version: u64,
    pub grant_blind: F,
    pub grant_next_blind: F,
    pub grant_expiry: u64,
    pub agent_secret: F,
    pub recipient: F,
    pub payment: u64,
    pub payment_blind: F,
    pub input_position: u16,
    pub input_value: u64,
    pub input_expiry: u64,
    pub input_note_secret: F,
    pub input_blind: F,
    pub path: [F; 4],
    pub change_value: u64,
    pub change_key: F,
    pub change_expiry: u64,
    pub change_note_secret: F,
    pub change_blind: F,
    pub payment_expiry: u64,
    pub payment_note_secret: F,
}

#[derive(Clone, Debug)]
pub struct Assignment {
    pub public: Statement,
    pub witness: Witness,
}

pub fn integer(f: F) -> Option<u64> {
    let bytes = f.to_repr();
    if bytes[8..].iter().any(|b| *b != 0) {
        return None;
    }
    Some(u64::from_le_bytes(bytes[..8].try_into().ok()?))
}

pub fn parent(a: &Assignment, next: bool) -> F {
    let w = &a.witness;
    let debit = u128::from(w.payment) + u128::from(integer(a.public[17]).unwrap_or(u64::MAX));
    let spent = u128::from(w.parent_spent) + if next { debit } else { 0 };
    let version = u128::from(w.parent_version) + u128::from(next);
    hash([
        F::from(500),
        a.public[1],
        a.public[2],
        a.public[3],
        a.public[5],
        a.public[14],
        a.public[28],
        F::from(w.parent_cap),
        F::from_u128(spent),
        F::from_u128(version),
        if next {
            w.parent_next_blind
        } else {
            w.parent_blind
        },
    ])
}

pub fn agent_key(secret: F) -> F {
    hash([F::from(510), secret])
}

pub fn grant(a: &Assignment, next: bool) -> F {
    let w = &a.witness;
    let debit = u128::from(w.payment) + u128::from(integer(a.public[17]).unwrap_or(u64::MAX));
    let spent = u128::from(w.grant_spent) + if next { debit } else { 0 };
    let version = u128::from(w.grant_version) + u128::from(next);
    hash([
        F::from(501),
        a.public[1],
        a.public[2],
        a.public[3],
        a.public[5],
        a.public[6],
        a.public[14],
        a.public[26],
        a.public[28],
        agent_key(w.agent_secret),
        w.recipient,
        F::from(w.grant_cap),
        F::from_u128(spent),
        F::from_u128(version),
        F::from(w.grant_expiry),
        if next {
            w.grant_next_blind
        } else {
            w.grant_blind
        },
    ])
}

pub fn payment(a: &Assignment) -> F {
    hash([
        F::from(502),
        a.public[1],
        a.public[2],
        a.public[3],
        a.public[18],
        a.public[26],
        a.public[28],
        a.witness.recipient,
        F::from(a.witness.payment),
        a.witness.payment_blind,
    ])
}

pub fn authorization(public: &Statement) -> F {
    let mut fields = [F::ZERO; 25];
    fields[0] = F::from(505);
    fields[1..20].copy_from_slice(&public[..19]);
    fields[20..].copy_from_slice(&public[25..]);
    hash(fields)
}

pub fn derived(a: &mut Assignment) {
    a.public[7] = parent(a, false);
    a.public[8] = grant(a, false);
    a.public[9] = parent(a, true);
    a.public[10] = grant(a, true);
    a.public[11] = hash([
        F::from(503),
        a.public[7],
        a.public[5],
        a.public[14],
        F::from(a.witness.parent_version),
    ]);
    a.public[12] = hash([
        F::from(504),
        a.public[8],
        a.public[6],
        a.public[14],
        F::from(a.witness.grant_version),
    ]);
    a.public[13] = payment(a);
    a.public[19] = authorization(&a.public);
    a.public[20] = note_root(input_note(a), a.witness.input_position, a.witness.path);
    a.public[21] = value_nullifier(a);
    a.public[22] = merchant_note(a);
    a.public[23] = change_note(a);
    a.public[24] = composite_binding(&a.public);
}

pub fn validate(a: &Assignment) -> Result<(), &'static str> {
    let p = &a.public;
    let w = &a.witness;
    let total = w
        .payment
        .checked_add(w.change_value)
        .and_then(|v| v.checked_add(integer(p[17])?));
    if total != Some(w.input_value) || w.input_value == 0 || w.change_value == 0 {
        return Err("value-conservation");
    }
    if w.change_key != agent_key(w.agent_secret) || w.change_expiry != w.input_expiry {
        return Err("restricted-change");
    }
    if w.input_position >= 16
        || w.input_expiry < integer(p[16]).ok_or("height")?
        || w.payment_expiry < integer(p[16]).ok_or("height")?
    {
        return Err("note-expiry-position");
    }
    if [
        w.input_note_secret,
        w.input_blind,
        w.change_note_secret,
        w.change_blind,
        w.payment_note_secret,
    ]
    .iter()
    .any(|v| *v == F::ZERO)
        || p[20..24].iter().any(|v| *v == F::ZERO)
        || p[22] == p[23]
    {
        return Err("note-zero");
    }
    if p[0] != F::from(2) {
        return Err("version");
    }
    integer(p[25]).ok_or("owner-sequence-range")?;
    if integer(p[26]).ok_or("grant-generation-range")? == 0
        || integer(p[28]).ok_or("owner-epoch-range")? == 0
        || p[27] == F::ZERO
        || p[29] == F::ZERO
        || p[29] != agent_key(w.agent_secret)
    {
        return Err("owner-grant-metadata");
    }
    let epoch = integer(p[14]).ok_or("epoch-range")?;
    let from = integer(p[15]).ok_or("from-range")?;
    let until = integer(p[16]).ok_or("until-range")?;
    let fee = integer(p[17]).ok_or("fee-range")?;
    let _ = epoch;
    if from >= until || until > w.grant_expiry {
        return Err("expiry");
    }
    if w.payment == 0
        || w.agent_secret == F::ZERO
        || w.recipient == F::ZERO
        || w.parent_blind == F::ZERO
        || w.parent_next_blind == F::ZERO
        || w.grant_blind == F::ZERO
        || w.grant_next_blind == F::ZERO
        || w.payment_blind == F::ZERO
    {
        return Err("zero-witness");
    }
    let debit = w.payment.checked_add(fee).ok_or("debit-overflow")?;
    let ps = w.parent_spent.checked_add(debit).ok_or("parent-overflow")?;
    let gs = w.grant_spent.checked_add(debit).ok_or("grant-overflow")?;
    if ps > w.parent_cap || gs > w.grant_cap {
        return Err("cap");
    }
    w.parent_version
        .checked_add(1)
        .ok_or("parent-version-overflow")?;
    w.grant_version
        .checked_add(1)
        .ok_or("grant-version-overflow")?;
    if p[..19].iter().any(|f| *f == F::ZERO) {
        return Err("zero-public");
    }
    let mut expected = a.clone();
    derived(&mut expected);
    if expected.public != *p {
        return Err("derived-binding");
    }
    Ok(())
}

pub fn fixture(agent: u64) -> Assignment {
    let mut p = [F::ZERO; PUBLIC_COUNT];
    p[0] = F::from(2);
    p[1] = F::from(11);
    p[2] = F::from(12);
    p[3] = F::from(13);
    p[4] = F::from(14);
    p[5] = F::from(15);
    p[6] = F::from(agent);
    p[14] = F::ONE;
    p[15] = F::ONE;
    p[16] = F::from(20);
    p[17] = F::from(2);
    p[18] = F::from(21 + agent);
    let w = Witness {
        parent_cap: 10,
        parent_spent: 0,
        parent_version: 1,
        parent_blind: F::from(31),
        parent_next_blind: F::from(32 + agent),
        grant_cap: 8,
        grant_spent: 0,
        grant_version: 1,
        grant_blind: F::from(40 + agent),
        grant_next_blind: F::from(50 + agent),
        grant_expiry: 30,
        agent_secret: F::from(60 + agent),
        recipient: F::from(70 + agent),
        payment: 4,
        payment_blind: F::from(80 + agent),
        input_position: 0,
        input_value: 10,
        input_expiry: 30,
        input_note_secret: F::from(90 + agent),
        input_blind: F::from(100 + agent),
        path: [F::ONE; 4],
        change_value: 4,
        change_key: agent_key(F::from(60 + agent)),
        change_expiry: 30,
        change_note_secret: F::from(110 + agent),
        change_blind: F::from(120 + agent),
        payment_expiry: 30,
        payment_note_secret: F::from(130 + agent),
    };
    let mut a = Assignment {
        public: p,
        witness: w,
    };
    a.public[25] = F::ZERO;
    a.public[26] = F::ONE;
    a.public[27] = crate::context::owner_key_commitment(crate::context::FIXTURE_OWNER_KEY);
    a.public[28] = F::ONE;
    a.public[29] = agent_key(a.witness.agent_secret);
    derived(&mut a);
    a
}

// This component uses distinct note/tree domains, never P5 commitments.
pub fn restricted_note(a: &Assignment, value: u64, expiry: u64, key: F, secret: F, blind: F) -> F {
    hash([
        F::from(600),
        a.public[1],
        a.public[2],
        a.public[3],
        a.public[5],
        a.public[6],
        a.public[14],
        a.public[26],
        a.public[28],
        F::from(expiry),
        F::from(value),
        key,
        secret,
        blind,
    ])
}
pub fn input_note(a: &Assignment) -> F {
    let w = &a.witness;
    restricted_note(
        a,
        w.input_value,
        w.input_expiry,
        agent_key(w.agent_secret),
        w.input_note_secret,
        w.input_blind,
    )
}
pub fn change_note(a: &Assignment) -> F {
    let w = &a.witness;
    restricted_note(
        a,
        w.change_value,
        w.change_expiry,
        w.change_key,
        w.change_note_secret,
        w.change_blind,
    )
}
pub fn merchant_note(a: &Assignment) -> F {
    let w = &a.witness;
    hash([
        F::from(604),
        a.public[1],
        a.public[2],
        a.public[3],
        a.public[18],
        a.public[26],
        a.public[28],
        F::from(w.payment_expiry),
        F::from(w.payment),
        w.recipient,
        w.payment_note_secret,
        w.payment_blind,
    ])
}
pub fn value_nullifier(a: &Assignment) -> F {
    let w = &a.witness;
    hash([
        F::from(603),
        a.public[1],
        a.public[2],
        a.public[3],
        a.public[5],
        a.public[6],
        a.public[14],
        a.public[26],
        a.public[28],
        w.agent_secret,
        w.input_note_secret,
        input_note(a),
        F::from(u64::from(w.input_position)),
    ])
}
pub fn note_root(commit: F, position: u16, path: [F; 4]) -> F {
    let mut node = hash([F::from(601), commit]);
    for (level, sibling) in path.into_iter().enumerate() {
        node = if (position >> level) & 1 == 0 {
            hash([F::from(602), node, sibling])
        } else {
            hash([F::from(602), sibling, node])
        };
    }
    node
}
pub fn tree(commits: &[F]) -> Result<(F, Vec<[F; 4]>), &'static str> {
    if commits.len() > 16 {
        return Err("tree-capacity");
    }
    let mut leaves = [F::ZERO; 16];
    leaves[..commits.len()].copy_from_slice(commits);
    let mut levels = vec![leaves
        .into_iter()
        .map(|c| hash([F::from(601), c]))
        .collect::<Vec<_>>()];
    for i in 0..4 {
        levels.push(
            levels[i]
                .chunks_exact(2)
                .map(|p| hash([F::from(602), p[0], p[1]]))
                .collect(),
        );
    }
    let paths = (0..commits.len())
        .map(|p| std::array::from_fn(|l| levels[l][(p >> l) ^ 1]))
        .collect();
    Ok((levels[4][0], paths))
}
pub fn composite_binding(p: &Statement) -> F {
    let mut fields = [F::ZERO; 30];
    fields[0] = F::from(525);
    fields[1..25].copy_from_slice(&p[..24]);
    fields[25..].copy_from_slice(&p[25..]);
    hash(fields)
}
pub fn fixture_pair() -> (crate::context::Context, Assignment, Assignment) {
    fixture_pair_domain(F::from(11))
}
pub fn fixture_pair_domain(genesis: F) -> (crate::context::Context, Assignment, Assignment) {
    let mut a = fixture(2);
    let mut b = fixture(3);
    a.public[1] = genesis;
    b.public[1] = genesis;
    derived(&mut a);
    derived(&mut b);
    let (_, paths) = tree(&[input_note(&a), input_note(&b)]).unwrap();
    a.witness.path = paths[0];
    b.witness.path = paths[1];
    b.witness.input_position = 1;
    derived(&mut a);
    derived(&mut b);
    let context = crate::context::Context {
        genesis: a.public[1],
        asset: a.public[2],
        mission: a.public[3],
        parent_id: a.public[5],
        epoch: 1,
        parent: a.public[7],
        owner_key: crate::context::FIXTURE_OWNER_KEY,
        owner_sequence: 0,
        owner_epoch: 1,
        grants: [
            (a.public[6], 1, a.public[8], a.public[29]),
            (b.public[6], 1, b.public[8], b.public[29]),
        ],
        fee: 2,
    };
    a.public[4] = context.root();
    b.public[4] = context.root();
    derived(&mut a);
    derived(&mut b);
    (context, a, b)
}
