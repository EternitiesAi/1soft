#![cfg(feature = "dev-prover")]

use shielded_consensus_halo2::{
    constants::{K, MAX_PROOF_BYTES},
    field::F,
    fixture::SyntheticFixture,
    profile::GeneratedProfile,
    prover::ProvingProfile,
};

#[test]
fn generated_profile_qualifies_k13_and_kat() {
    assert_eq!(K, 13);
    let proving = ProvingProfile::new().expect("construct proving profile");
    let fixture = SyntheticFixture::one_note();

    let first = proving
        .prove_live(fixture.assignment.clone())
        .expect("first live proof");
    let second = proving
        .prove_live(fixture.assignment.clone())
        .expect("second live proof");
    assert_ne!(first, second, "live proofs must use fresh OS randomness");
    assert_eq!(first.len(), second.len());
    assert!(first.len() < MAX_PROOF_BYTES);
    proving
        .verifier()
        .verify(&fixture.assignment.public, &first)
        .expect("valid proof verifies");

    for tweak in [51u64, 52, 53] {
        let mut assignment = fixture.assignment.clone();
        assignment.witness.input_blinding += F::from(tweak);
        assignment
            .rebuild_derived()
            .expect("rebuild randomized valid witness");
        let proof = proving.prove_live(assignment.clone()).expect("randomized proof");
        assert_eq!(proof.len(), first.len(), "proof length must remain fixed");
        proving
            .verifier()
            .verify(&assignment.public, &proof)
            .expect("randomized proof verifies");
    }

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("shielded-consensus directory");
    let generated = GeneratedProfile::build(root).expect("generate deterministic profile");
    assert_eq!(generated.descriptor.exact_proof_length as usize, first.len());
    assert_eq!(generated.kat.proof.len(), first.len());
    proving
        .verifier()
        .verify_public_bytes(&generated.kat.public_inputs, &generated.kat.proof)
        .expect("KAT proof verifies");
    let mut mutated = generated.kat.proof.clone();
    mutated[generated.kat.mutation_offset as usize] ^= generated.kat.xor_mask;
    assert!(
        proving
            .verifier()
            .verify_public_bytes(&generated.kat.public_inputs, &mutated)
            .is_err(),
        "prescribed KAT mutation must fail"
    );
    assert!(generated.identity_dag_is_acyclic());
    let profile_dir = root.join("profile");
    let tracked_descriptor = std::fs::read(profile_dir.join("profile-descriptor-v1.bin"))
        .expect("read tracked descriptor");
    let tracked_kat = std::fs::read(profile_dir.join("kat-v1.bin"))
        .expect("read tracked KAT");
    assert_eq!(
        tracked_descriptor,
        generated.descriptor.encode().expect("encode generated descriptor"),
        "tracked descriptor must be a current deterministic regeneration"
    );
    assert_eq!(
        tracked_kat,
        generated.kat.encode().expect("encode generated KAT"),
        "tracked KAT must be a current deterministic regeneration"
    );
    let manifest = std::fs::read_to_string(profile_dir.join("profile-manifest-v1.json"))
        .expect("read profile manifest");
    assert!(!manifest.contains("descriptor_hash"));
    assert!(!manifest.contains("worker_binary_hash"));
}
