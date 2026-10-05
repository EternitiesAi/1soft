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
        F::from(200),
        a.public[1],
        a.public[2],
        a.public[3],
        a.public[5],
        a.public[14],
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
    hash([F::from(210), secret])
}

pub fn grant(a: &Assignment, next: bool) -> F {
    let w = &a.witness;
    let debit = u128::from(w.payment) + u128::from(integer(a.public[17]).unwrap_or(u64::MAX));
    let spent = u128::from(w.grant_spent) + if next { debit } else { 0 };
    let version = u128::from(w.grant_version) + u128::from(next);
    hash([
        F::from(201),
        a.public[1],
        a.public[2],
        a.public[3],
        a.public[5],
        a.public[6],
        a.public[14],
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
        F::from(202),
        a.public[1],
        a.public[2],
        a.public[3],
        a.public[18],
        a.witness.recipient,
        F::from(a.witness.payment),
        a.witness.payment_blind,
    ])
}

pub fn authorization(public: &Statement) -> F {
    let mut fields = [F::ZERO; PUBLIC_COUNT];
    fields[0] = F::from(205);
    fields[1..].copy_from_slice(&public[..PUBLIC_COUNT - 1]);
    hash(fields)
}

pub fn derived(a: &mut Assignment) {
    a.public[7] = parent(a, false);
    a.public[8] = grant(a, false);
    a.public[9] = parent(a, true);
    a.public[10] = grant(a, true);
    a.public[11] = hash([
        F::from(203),
        a.public[7],
        a.public[5],
        a.public[14],
        F::from(a.witness.parent_version),
    ]);
    a.public[12] = hash([
        F::from(204),
        a.public[8],
        a.public[6],
        a.public[14],
        F::from(a.witness.grant_version),
    ]);
    a.public[13] = payment(a);
    a.public[19] = authorization(&a.public);
}

pub fn validate(a: &Assignment) -> Result<(), &'static str> {
    let p = &a.public;
    let w = &a.witness;
    if p[0] != F::ONE {
        return Err("version");
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
    p[0] = F::ONE;
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
    };
    let mut a = Assignment {
        public: p,
        witness: w,
    };
    derived(&mut a);
    a
}
