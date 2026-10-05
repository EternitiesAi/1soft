use crate::{
    circuit::AuthorityCircuit,
    relation::{validate, Assignment, Statement},
    K,
};
use halo2_proofs::{
    pasta::EqAffine,
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite, Challenge255},
};
use rand::{rngs::StdRng, SeedableRng};

pub struct Profile {
    params: Params<EqAffine>,
    pk: ProvingKey<EqAffine>,
}
impl Profile {
    pub fn identities(&self) -> Result<([u8; 32], [u8; 32]), &'static str> {
        use sha2::{Digest, Sha256};
        let mut params = Vec::new();
        self.params.write(&mut params).map_err(|_| "parameters")?;
        let vk = format!("{:?}", self.pk.get_vk().pinned());
        Ok((
            Sha256::digest(params).into(),
            Sha256::digest(vk.as_bytes()).into(),
        ))
    }
    pub fn new() -> Result<Self, &'static str> {
        let params = Params::new(K);
        let empty = AuthorityCircuit::default();
        let vk = keygen_vk(&params, &empty).map_err(|_| "keygen")?;
        let pk = keygen_pk(&params, vk, &empty).map_err(|_| "keygen")?;
        Ok(Self { params, pk })
    }
    pub fn prove(&self, a: Assignment, seed: [u8; 32]) -> Result<Vec<u8>, &'static str> {
        validate(&a)?;
        let public = a.public;
        let mut t = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(Vec::new());
        create_proof(
            &self.params,
            &self.pk,
            &[AuthorityCircuit::new(a)],
            &[&[&public]],
            StdRng::from_seed(seed),
            &mut t,
        )
        .map_err(|_| "prove")?;
        let proof = t.finalize();
        self.verify(&public, &proof)?;
        Ok(proof)
    }
    pub fn verify(&self, p: &Statement, proof: &[u8]) -> Result<(), &'static str> {
        if proof.len() != crate::PROOF_BYTES {
            return Err("proof-bound");
        }
        let strategy = SingleVerifier::new(&self.params);
        let mut cursor = std::io::Cursor::new(proof);
        {
            let mut t = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(&mut cursor);
            verify_proof(&self.params, self.pk.get_vk(), strategy, &[&[p]], &mut t)
                .map_err(|_| "proof")?;
        }
        if cursor.position() != proof.len() as u64 {
            return Err("proof-trailing");
        }
        Ok(())
    }
}
