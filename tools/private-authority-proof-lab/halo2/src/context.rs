//! One trusted local coordinator. This is not consensus or a current-state certificate.
use crate::{proof::Profile, relation::Statement, F};
use ff::Field;
use shielded_consensus_halo2::tree::native_hash as hash;

#[derive(Clone, Debug)]
pub struct Context {
    pub genesis: F,
    pub asset: F,
    pub mission: F,
    pub parent_id: F,
    pub epoch: u64,
    pub parent: F,
    pub grants: [(F, F); 2],
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
            || self.epoch == 0
            || self.fee == 0
            || self.grants[0].0 == self.grants[1].0
        {
            return Err("context-invariant");
        }
        Ok(())
    }
    pub fn root(&self) -> F {
        hash([
            F::from(220),
            self.genesis,
            self.asset,
            self.mission,
            self.parent_id,
            F::from(self.epoch),
            self.parent,
            self.grants[0].0,
            self.grants[0].1,
            self.grants[1].0,
            self.grants[1].1,
        ])
    }
    pub fn check(&self, p: &Statement, height: u64) -> Result<usize, &'static str> {
        self.validate()?;
        if p[0] != F::ONE
            || p[1] != self.genesis
            || p[2] != self.asset
            || p[3] != self.mission
            || p[4] != self.root()
            || p[5] != self.parent_id
            || p[7] != self.parent
            || p[14] != F::from(self.epoch)
            || p[17] != F::from(self.fee)
        {
            return Err("stale-context");
        }
        let index = self
            .grants
            .iter()
            .position(|(id, commit)| *id == p[6] && *commit == p[8] && *commit != F::ZERO)
            .ok_or("stale-grant")?;
        let from = crate::relation::integer(p[15]).ok_or("height")?;
        let until = crate::relation::integer(p[16]).ok_or("height")?;
        if height < from || height >= until {
            return Err("height");
        }
        Ok(index)
    }
    pub fn commit(
        &mut self,
        profile: &Profile,
        p: &Statement,
        proof: &[u8],
        height: u64,
    ) -> Result<(), &'static str> {
        let index = self.check(p, height)?;
        profile.verify(p, proof)?;
        self.parent = p[9];
        self.grants[index].1 = p[10];
        Ok(())
    }
    // Trusted operator seam only. No owner authorization/recovery claim.
    pub fn revoke(&mut self, id: F) -> Result<(), &'static str> {
        self.validate()?;
        let index = self
            .grants
            .iter()
            .position(|(key, _)| *key == id)
            .ok_or("grant")?;
        self.grants[index].1 = F::ZERO;
        Ok(())
    }
}
