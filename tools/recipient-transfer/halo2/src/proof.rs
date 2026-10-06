use crate::{
    circuit::TransferCircuit,
    relation::{validate, Assignment},
    verifier::Verifier,
};
use halo2_proofs::{
    pasta::EqAffine,
    plonk::{create_proof, keygen_pk, ProvingKey},
    transcript::{Blake2bWrite, Challenge255},
};
use rand::{rngs::StdRng, SeedableRng};
pub struct Profile {
    verifier: Verifier,
    pk: ProvingKey<EqAffine>,
}
impl Profile {
    pub fn new() -> Result<Self, &'static str> {
        let verifier = Verifier::new()?;
        let pk = keygen_pk(
            &verifier.params,
            verifier.vk.clone(),
            &TransferCircuit::default(),
        )
        .map_err(|_| "keygen")?;
        Ok(Self { verifier, pk })
    }
    pub fn prove(&self, a: Assignment, seed: [u8; 32]) -> Result<Vec<u8>, &'static str> {
        validate(&a)?;
        let p = a.public;
        let mut t = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(Vec::new());
        create_proof(
            &self.verifier.params,
            &self.pk,
            &[TransferCircuit::new(a)],
            &[&[&p]],
            StdRng::from_seed(seed),
            &mut t,
        )
        .map_err(|_| "prove")?;
        let proof = t.finalize();
        self.verifier.verify(&p, &proof)?;
        Ok(proof)
    }
}
