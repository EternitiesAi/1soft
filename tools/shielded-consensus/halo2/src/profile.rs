use std::{fs, path::Path};

use sha2::{Digest, Sha256};

use crate::{
    encoding::{Digest32, KatV1, ProfileDescriptorV1},
    verifier::{PinnedVerifier, VerifyError},
};

pub const SOURCE_PATHS: [&str; 11] = [
    "halo2/Cargo.toml",
    "halo2/src/circuit.rs",
    "halo2/src/constants.rs",
    "halo2/src/encoding.rs",
    "halo2/src/field.rs",
    "halo2/src/fixture.rs",
    "halo2/src/profile.rs",
    "halo2/src/prover.rs",
    "halo2/src/relation.rs",
    "halo2/src/tree.rs",
    "halo2/src/verifier.rs",
];

pub const CURVE_COMMITMENT_IDENTITY: &[u8] =
    b"pasta-curves-0.6.0:pallas-base:vesta-ipa:halo2-proofs-0.4.0";
pub const TRANSCRIPT_POSEIDON_IDENTITY: &[u8] =
    b"blake2b-write-read:challenge255:p128pow5t3:halo2-gadgets-0.6.0";
const SOURCE_DOMAIN: &[u8] = b"1soft/shielded-circuit-source/v1\0";
#[cfg(feature = "dev-prover")]
const KAT_SEED: [u8; 32] = [0x5au8; 32];

pub fn sha256(bytes: &[u8]) -> Digest32 {
    Sha256::digest(bytes).into()
}

pub fn circuit_source_hash(root: &Path) -> Result<Digest32, String> {
    let mut hasher = Sha256::new();
    hasher.update(SOURCE_DOMAIN);
    for relative in SOURCE_PATHS {
        let bytes = fs::read(root.join(relative))
            .map_err(|error| format!("read source {relative}: {error}"))?;
        let path = relative.as_bytes();
        hasher.update(
            u32::try_from(path.len())
                .map_err(|_| "source path too long".to_string())?
                .to_le_bytes(),
        );
        hasher.update(path);
        hasher.update(
            u64::try_from(bytes.len())
                .map_err(|_| "source file too long".to_string())?
                .to_le_bytes(),
        );
        hasher.update(bytes);
    }
    Ok(hasher.finalize().into())
}

fn file_hash(path: &Path) -> Result<Digest32, String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    Ok(sha256(&bytes))
}

pub fn runtime_descriptor(
    root: &Path,
    verifier: &PinnedVerifier,
    exact_proof_length: usize,
    kat: &KatV1,
) -> Result<ProfileDescriptorV1, String> {
    Ok(ProfileDescriptorV1 {
        exact_proof_length: u32::try_from(exact_proof_length)
            .map_err(|_| "proof length overflow".to_string())?,
        parameter_hash: verifier
            .parameter_hash()
            .map_err(|_| "parameter hashing failed".to_string())?,
        verifying_key_hash: verifier
            .verifying_key_hash()
            .map_err(|_| "verifying-key hashing failed".to_string())?,
        circuit_source_hash: circuit_source_hash(root)?,
        cargo_lock_hash: file_hash(&root.join("halo2/Cargo.lock"))?,
        profile_manifest_hash: file_hash(&root.join("profile/profile-manifest-v1.json"))?,
        public_schema_hash: file_hash(&root.join("profile/public-schema-v1.json"))?,
        kat_hash: kat.identity_hash(),
        curve_commitment_hash: sha256(CURVE_COMMITMENT_IDENTITY),
        transcript_poseidon_hash: sha256(TRANSCRIPT_POSEIDON_IDENTITY),
    })
}

pub fn load_artifacts(profile_dir: &Path) -> Result<(ProfileDescriptorV1, KatV1), String> {
    let descriptor_bytes = fs::read(profile_dir.join("profile-descriptor-v1.bin"))
        .map_err(|error| format!("read profile descriptor: {error}"))?;
    let kat_bytes = fs::read(profile_dir.join("kat-v1.bin"))
        .map_err(|error| format!("read KAT: {error}"))?;
    let descriptor = ProfileDescriptorV1::decode(&descriptor_bytes)
        .map_err(|error| format!("decode profile descriptor: {error}"))?;
    let kat = KatV1::decode(&kat_bytes).map_err(|error| format!("decode KAT: {error}"))?;
    Ok((descriptor, kat))
}

pub fn validate_pinned_cryptography(
    verifier: &PinnedVerifier,
    descriptor: &ProfileDescriptorV1,
    kat: &KatV1,
) -> Result<(), String> {
    if descriptor.exact_proof_length as usize != kat.proof.len()
        || descriptor.parameter_hash
            != verifier.parameter_hash().map_err(|_| "parameter hashing failed".to_string())?
        || descriptor.verifying_key_hash
            != verifier.verifying_key_hash().map_err(|_| "verifying-key hashing failed".to_string())?
        || descriptor.kat_hash != kat.identity_hash()
        || descriptor.curve_commitment_hash != sha256(CURVE_COMMITMENT_IDENTITY)
        || descriptor.transcript_poseidon_hash != sha256(TRANSCRIPT_POSEIDON_IDENTITY)
    {
        return Err("profile does not match pinned cryptography".to_string());
    }
    verifier
        .verify_public_bytes(&kat.public_inputs, &kat.proof)
        .map_err(|_| "KAT proof failed".to_string())?;
    let mut mutated = kat.proof.clone();
    mutated[kat.mutation_offset as usize] ^= kat.xor_mask;
    match verifier.verify_public_bytes(&kat.public_inputs, &mutated) {
        Err(VerifyError::InvalidProof) => Ok(()),
        _ => Err("KAT prescribed mutation did not fail as InvalidProof".to_string()),
    }
}

pub fn validate_runtime_artifacts(
    root: &Path,
    verifier: &PinnedVerifier,
    descriptor: &ProfileDescriptorV1,
    kat: &KatV1,
) -> Result<(), String> {
    validate_pinned_cryptography(verifier, descriptor, kat)?;
    let expected = runtime_descriptor(root, verifier, kat.proof.len(), kat)?;
    if &expected != descriptor {
        return Err("profile descriptor does not match pinned runtime".to_string());
    }
    Ok(())
}

#[cfg(feature = "dev-prover")]
pub struct GeneratedProfile {
    pub descriptor: ProfileDescriptorV1,
    pub kat: KatV1,
}

#[cfg(feature = "dev-prover")]
impl GeneratedProfile {
    pub fn build(root: &Path) -> Result<Self, String> {
        use crate::{fixture::SyntheticFixture, prover::ProvingProfile};

        let proving = ProvingProfile::new()
            .map_err(|_| "construct pinned proving profile failed".to_string())?;
        let fixture = SyntheticFixture::one_note();
        let proof = proving
            .prove_seeded(fixture.assignment.clone(), KAT_SEED)
            .map_err(|_| "deterministic KAT proof failed".to_string())?;
        if proof.is_empty() || proof.len() >= crate::constants::MAX_PROOF_BYTES {
            return Err("K=13 proof does not meet proof-size ceiling".to_string());
        }
        let kat = KatV1 {
            public_inputs: fixture.assignment.public.to_field_bytes(),
            mutation_offset: u32::try_from(proof.len() / 2)
                .map_err(|_| "KAT mutation offset overflow".to_string())?,
            proof,
            expected_status: 0,
            xor_mask: 1,
        };
        let descriptor = runtime_descriptor(root, proving.verifier(), kat.proof.len(), &kat)?;
        validate_runtime_artifacts(root, proving.verifier(), &descriptor, &kat)?;
        Ok(Self { descriptor, kat })
    }

    pub fn write_to(&self, directory: &Path) -> Result<(), String> {
        fs::create_dir_all(directory)
            .map_err(|error| format!("create {}: {error}", directory.display()))?;
        let descriptor = self
            .descriptor
            .encode()
            .map_err(|error| format!("encode profile descriptor: {error}"))?;
        let kat = self
            .kat
            .encode()
            .map_err(|error| format!("encode KAT: {error}"))?;
        fs::write(directory.join("profile-descriptor-v1.bin"), descriptor)
            .map_err(|error| format!("write profile descriptor: {error}"))?;
        fs::write(directory.join("kat-v1.bin"), kat)
            .map_err(|error| format!("write KAT: {error}"))?;
        Ok(())
    }

    pub fn identity_dag_is_acyclic(&self) -> bool {
        SOURCE_PATHS.iter().all(|path| {
            !path.ends_with("profile-descriptor-v1.bin") && !path.ends_with("kat-v1.bin")
        }) && self.descriptor.kat_hash == self.kat.identity_hash()
    }
}
