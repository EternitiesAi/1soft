//! Verifier-only P7 bridge; no fixtures, openings, proving or ledger operations.
use ff::{Field, PrimeField};
use halo2_proofs::{
    pasta::EqAffine,
    plonk::{keygen_vk, verify_proof, SingleVerifier, VerifyingKey},
    poly::commitment::Params,
    transcript::{Blake2bRead, Challenge255},
};
use owner_treasury_lab::{
    circuit::TreasuryCircuit,
    relation::tree,
    wire::{decode, fields},
    F,
};
use sha2::{Digest, Sha256};
use shielded_consensus_halo2::tree::native_hash;
use std::io::{self, Read, Write};
struct Verifier {
    params: Params<EqAffine>,
    vk: VerifyingKey<EqAffine>,
}
impl Verifier {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let params = Params::new(owner_treasury_lab::K);
        let vk = keygen_vk(&params, &TreasuryCircuit::default())?;
        let mut bytes = Vec::new();
        params.write(&mut bytes)?;
        let params_id = format!("{:x}", Sha256::digest(bytes));
        let vk_id = format!(
            "{:x}",
            Sha256::digest(format!("{:?}", vk.pinned()).as_bytes())
        );
        if params_id != "1cb278fe4d9cf5325e5cbc710d863c0deca3e961e1b8f6c8736890c43345c461"
            || vk_id != "a02861479050d671419f1e2146410ab3130d3766185898de0140bac4743c17f2"
        {
            return Err("frozen-profile-differs".into());
        }
        Ok(Self { params, vk })
    }
    fn verify(
        &self,
        p: &owner_treasury_lab::relation::Statement,
        proof: &[u8],
    ) -> Result<(), &'static str> {
        if proof.len() != owner_treasury_lab::PROOF_BYTES {
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
            .map_err(|_| "proof")?;
        }
        if cursor.position() != proof.len() as u64 {
            return Err("proof-trailing");
        }
        Ok(())
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 2 {
        return Err("operation-bound".into());
    }
    if ![
        "verify",
        "context-root",
        "note-root",
        "owner-key",
        "network-domain",
        "identities",
    ]
    .contains(&args[1].as_str())
    {
        return Err("operation".into());
    }
    let mut raw = Vec::new();
    io::stdin().take(8193).read_to_end(&mut raw)?;
    if raw.len() > 8192 {
        return Err("input-bound".into());
    }
    let reply = match args[1].as_str() {
        "verify" => {
            // Profile/startup failure is fatal, distinct from invalid proof.
            let profile = Verifier::new()?;
            match decode(&raw) {
                Ok((p, proof)) if profile.verify(&p, proof).is_ok() => b"OK\n".to_vec(),
                _ => b"INVALID\n".to_vec(),
            }
        }
        "context-root" => {
            let f = fields(&raw)?;
            if f.len() != 18 {
                return Err("context-bound".into());
            }
            let mut v = [F::ZERO; 19];
            v[0] = F::from(520);
            v[1..].copy_from_slice(&f);
            native_hash(v).to_repr().as_ref().to_vec()
        }
        "owner-key" | "network-domain" => {
            let bytes: [u8; 32] = raw.try_into().map_err(|_| "digest-bound")?;
            let f = if args[1] == "owner-key" {
                owner_treasury_lab::context::owner_key_commitment(bytes)
            } else {
                owner_treasury_lab::context::network_domain(bytes)
            };
            f.to_repr().as_ref().to_vec()
        }
        "identities" => {
            if !raw.is_empty() {
                return Err("identity-bound".into());
            }
            let _ = Verifier::new()?;
            b"{\"parameter_sha256\":\"1cb278fe4d9cf5325e5cbc710d863c0deca3e961e1b8f6c8736890c43345c461\",\"verifying_key_sha256\":\"a02861479050d671419f1e2146410ab3130d3766185898de0140bac4743c17f2\"}\n".to_vec()
        }
        "note-root" => {
            let f = fields(&raw)?;
            tree(&f)?.0.to_repr().as_ref().to_vec()
        }
        _ => return Err("operation".into()),
    };
    io::stdout().write_all(&reply)?;
    Ok(())
}
