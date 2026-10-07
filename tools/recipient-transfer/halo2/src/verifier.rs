use crate::{circuit::TransferCircuit, profile_pins, relation::Statement, K, PROOF_BYTES};
use halo2_proofs::{
    pasta::EqAffine,
    plonk::{keygen_vk, verify_proof, SingleVerifier, VerifyingKey},
    poly::commitment::Params,
    transcript::{Blake2bRead, Challenge255},
};
use sha2::{Digest, Sha256};
pub struct Verifier {
    pub(crate) params: Params<EqAffine>,
    pub(crate) vk: VerifyingKey<EqAffine>,
}
impl Verifier {
    /// Inspect the actual parameters/key already checked by `new`.
    /// This does not construct another verifier or bypass the profile pins.
    pub fn identities(&self) -> Result<(String, String), &'static str> {
        identities(&self.params, &self.vk)
    }
    pub fn inspect() -> Result<(String, String), &'static str> {
        let params = Params::new(K);
        let vk = keygen_vk(&params, &TransferCircuit::default()).map_err(|_| "keygen")?;
        identities(&params, &vk)
    }
    pub fn new() -> Result<Self, &'static str> {
        let params = Params::new(K);
        let vk = keygen_vk(&params, &TransferCircuit::default()).map_err(|_| "keygen")?;
        let (p, v) = identities(&params, &vk)?;
        if p != profile_pins::PARAMS || v != profile_pins::VK {
            return Err("profile-pins");
        }
        Ok(Self { params, vk })
    }
    pub fn verify(&self, p: &Statement, proof: &[u8]) -> Result<(), &'static str> {
        if proof.len() != PROOF_BYTES {
            return Err("proof-bound");
        }
        let mut cursor = std::io::Cursor::new(proof);
        {
            let mut t = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(&mut cursor);
            verify_proof(
                &self.params,
                &self.vk,
                SingleVerifier::new(&self.params),
                &[&[p]],
                &mut t,
            )
            .map_err(|_| "invalid-proof")?;
        }
        if cursor.position() != proof.len() as u64 {
            return Err("trailing-proof");
        }
        Ok(())
    }
}
pub(crate) fn identities(
    params: &Params<EqAffine>,
    vk: &VerifyingKey<EqAffine>,
) -> Result<(String, String), &'static str> {
    let mut b = Vec::new();
    params.write(&mut b).map_err(|_| "params")?;
    Ok((
        format!("{:x}", Sha256::digest(b)),
        format!(
            "{:x}",
            Sha256::digest(format!("{:?}", vk.pinned()).as_bytes())
        ),
    ))
}
