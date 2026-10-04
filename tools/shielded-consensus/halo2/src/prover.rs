use halo2_proofs::{
    pasta::EqAffine,
    plonk::{create_proof, keygen_pk, ProvingKey},
    transcript::{Blake2bWrite, Challenge255},
};
use rand::{rngs::StdRng, Rng, SeedableRng};

use crate::{
    circuit::NoteCircuit,
    relation::{validate_native, Assignment},
    verifier::{PinnedVerifier, VerifyError},
};

pub struct ProvingProfile {
    verifier: PinnedVerifier,
    proving_key: ProvingKey<EqAffine>,
}

impl ProvingProfile {
    pub fn new() -> Result<Self, VerifyError> {
        let verifier = PinnedVerifier::new()?;
        let proving_key = keygen_pk(
            &verifier.params,
            verifier.vk.clone(),
            &NoteCircuit::default(),
        )
        .map_err(|_| VerifyError::InternalFailure)?;
        Ok(Self {
            verifier,
            proving_key,
        })
    }

    fn prove_with_rng<R: Rng>(
        &self,
        assignment: Assignment,
        rng: R,
    ) -> Result<Vec<u8>, VerifyError> {
        validate_native(&assignment).map_err(|_| VerifyError::InvalidStatement)?;
        let instances = assignment.public.0;
        let circuit = NoteCircuit::new(assignment);
        let mut transcript = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(Vec::new());
        create_proof(
            &self.verifier.params,
            &self.proving_key,
            &[circuit],
            &[&[&instances]],
            rng,
            &mut transcript,
        )
        .map_err(|_| VerifyError::InternalFailure)?;
        let proof = transcript.finalize();
        self.verifier.verify(&crate::relation::PublicStatement(instances), &proof)?;
        Ok(proof)
    }

    pub fn prove_live(&self, assignment: Assignment) -> Result<Vec<u8>, VerifyError> {
        self.prove_with_rng(assignment, rand::rng())
    }

    pub fn prove_seeded(
        &self,
        assignment: Assignment,
        seed: [u8; 32],
    ) -> Result<Vec<u8>, VerifyError> {
        self.prove_with_rng(assignment, StdRng::from_seed(seed))
    }

    pub fn verifier(&self) -> &PinnedVerifier {
        &self.verifier
    }
}
