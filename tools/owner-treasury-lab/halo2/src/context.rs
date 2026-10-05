//! Native exact-current owner context; signed commands are a separate caller gate.
use crate::{
    relation::{integer, Statement},
    F,
};
use ff::{Field, PrimeField};
use shielded_consensus_halo2::tree::native_hash as hash;
pub const FIXTURE_OWNER_KEY: [u8; 32] = [
    234, 74, 108, 99, 226, 156, 82, 10, 190, 245, 80, 123, 19, 46, 197, 249, 149, 71, 118, 174,
    190, 190, 123, 146, 66, 30, 234, 105, 20, 70, 210, 44,
];
pub fn owner_key_commitment(key: [u8; 32]) -> F {
    let low = u128::from_le_bytes(key[..16].try_into().unwrap());
    let high = u128::from_le_bytes(key[16..].try_into().unwrap());
    hash([F::from(531), F::from_u128(low), F::from_u128(high)])
}
pub fn network_domain(digest: [u8; 32]) -> F {
    let low = u128::from_le_bytes(digest[..16].try_into().unwrap());
    let high = u128::from_le_bytes(digest[16..].try_into().unwrap());
    hash([F::from(532), F::from_u128(low), F::from_u128(high)])
}
#[derive(Clone, Debug)]
pub struct Context {
    pub genesis: F,
    pub asset: F,
    pub mission: F,
    pub parent_id: F,
    pub epoch: u64,
    pub owner_key: [u8; 32],
    pub owner_sequence: u64,
    pub owner_epoch: u64,
    pub parent: F,
    pub grants: [(F, u64, F, F); 2],
    pub fee: u64,
}
impl Context {
    pub fn validate(&self) -> Result<(), &'static str> {
        if [
            self.genesis,
            self.asset,
            self.mission,
            self.parent_id,
            self.parent,
            self.grants[0].0,
            self.grants[1].0,
        ]
        .iter()
        .any(|v| *v == F::ZERO)
            || self.owner_key == [0; 32]
            || self.epoch == 0
            || self.owner_epoch == 0
            || self.fee == 0
            || self.grants[0].0 == self.grants[1].0
        {
            return Err("owner-context-invariant");
        }
        for (_, generation, commit, key) in self.grants {
            if (generation == 0 && (commit != F::ZERO || key != F::ZERO))
                || (generation > 0 && key == F::ZERO)
            {
                return Err("owner-slot-invariant");
            }
        }
        Ok(())
    }
    // Frozen ordered19-field Poseidon encoding, including the domain.
    pub fn root(&self) -> F {
        hash([
            F::from(520),
            self.genesis,
            self.asset,
            self.mission,
            self.parent_id,
            F::from(self.epoch),
            F::from(self.owner_epoch),
            F::from(self.owner_sequence),
            owner_key_commitment(self.owner_key),
            self.parent,
            F::from(self.fee),
            self.grants[0].0,
            F::from(self.grants[0].1),
            self.grants[0].2,
            self.grants[0].3,
            self.grants[1].0,
            F::from(self.grants[1].1),
            self.grants[1].2,
            self.grants[1].3,
        ])
    }
    pub fn check(&self, p: &Statement, height: u64) -> Result<usize, &'static str> {
        self.validate()?;
        if p[0] != F::from(2)
            || p[1] != self.genesis
            || p[2] != self.asset
            || p[3] != self.mission
            || p[4] != self.root()
            || p[5] != self.parent_id
            || p[7] != self.parent
            || p[14] != F::from(self.epoch)
            || p[17] != F::from(self.fee)
            || p[25] != F::from(self.owner_sequence)
            || p[27] != owner_key_commitment(self.owner_key)
            || p[28] != F::from(self.owner_epoch)
        {
            return Err("stale-owner-context");
        }
        let index = self
            .grants
            .iter()
            .position(|(id, generation, commit, key)| {
                *id == p[6]
                    && F::from(*generation) == p[26]
                    && *commit == p[8]
                    && *commit != F::ZERO
                    && *key == p[29]
            })
            .ok_or("stale-owner-grant")?;
        let from = integer(p[15]).ok_or("height")?;
        let until = integer(p[16]).ok_or("height")?;
        if height < from || height >= until {
            return Err("height");
        }
        Ok(index)
    }
}
