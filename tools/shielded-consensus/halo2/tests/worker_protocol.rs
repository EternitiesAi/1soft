#![cfg(feature = "worker")]

use ff::Field;

use shielded_consensus_halo2::{
    constants::MAX_WORKER_FRAME_BYTES,
    encoding::{WorkerOpcode, WorkerRequestV1, WorkerStatus},
    field::{encode_field, F},
    fixture::SyntheticFixture,
    tree::tree_root,
    worker_protocol::{
        decode_append_response, encode_tree_root_payload, encode_verify_append_payload,
        encode_verify_proof_payload, DispatchResult, WorkerRuntime,
    },
};

#[test]
fn profile_tree_verify_and_append_round_trip() {
    let profile_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../profile");
    let mut runtime = WorkerRuntime::from_artifact_files(
        &profile_dir.join("profile-descriptor-v1.bin"),
        &profile_dir.join("kat-v1.bin"),
    )
    .expect("construct worker runtime and run startup KAT");
    let profile_id = runtime.profile_id();
    let fixture = SyntheticFixture::one_note();
    let kat = runtime.kat().clone();

    let profile = runtime
        .dispatch(WorkerRequestV1 {
            opcode: WorkerOpcode::Profile,
            request_id: 1,
            profile_id,
            payload: Vec::new(),
        })
        .expect("profile dispatch");
    assert_eq!(profile.response.status, WorkerStatus::Ok);
    assert_eq!(profile.response.payload, runtime.descriptor_bytes());
    assert!(!profile.terminate);

    let tree = runtime
        .dispatch(WorkerRequestV1 {
            opcode: WorkerOpcode::TreeRootV1,
            request_id: 2,
            profile_id,
            payload: encode_tree_root_payload(&fixture.commitments).unwrap(),
        })
        .expect("tree dispatch");
    assert_eq!(tree.response.status, WorkerStatus::Ok);
    assert_eq!(tree.response.payload, encode_field(fixture.assignment.public.0[8]));

    let proof = runtime
        .dispatch(WorkerRequestV1 {
            opcode: WorkerOpcode::VerifyProofV1,
            request_id: 3,
            profile_id,
            payload: encode_verify_proof_payload(&kat.public_inputs, &kat.proof).unwrap(),
        })
        .expect("proof dispatch");
    assert_eq!(proof.response.status, WorkerStatus::Ok);

    let append = runtime
        .dispatch(WorkerRequestV1 {
            opcode: WorkerOpcode::VerifyAndAppendV1,
            request_id: 4,
            profile_id,
            payload: {
                let mut current_commitments = fixture.commitments.clone();
                current_commitments.push(F::from(777));
                encode_verify_append_payload(
                    &current_commitments,
                    &kat.public_inputs,
                    &kat.proof,
                )
            }
            .unwrap(),
        })
        .expect("append dispatch");
    assert_eq!(append.response.status, WorkerStatus::Ok);
    let transition = decode_append_response(&append.response.payload).unwrap();
    let mut current_commitments = fixture.commitments.clone();
    current_commitments.push(F::from(777));
    assert_ne!(tree_root(&current_commitments).unwrap(), fixture.assignment.public.0[8]);
    assert_eq!(transition.root_before, tree_root(&current_commitments).unwrap());
    assert_eq!(transition.position_0, 2);
    assert_eq!(transition.position_1, 3);

    let mut bad_statement = kat.public_inputs;
    bad_statement[13] = encode_field(F::from(999));
    let invalid_statement = runtime
        .dispatch(WorkerRequestV1 {
            opcode: WorkerOpcode::VerifyProofV1,
            request_id: 5,
            profile_id,
            payload: encode_verify_proof_payload(&bad_statement, &kat.proof).unwrap(),
        })
        .unwrap();
    assert_eq!(invalid_statement.response.status, WorkerStatus::InvalidStatement);
    assert!(!invalid_statement.terminate);

    let mut bad_proof = kat.proof.clone();
    bad_proof[kat.mutation_offset as usize] ^= kat.xor_mask;
    let invalid_proof = runtime
        .dispatch(WorkerRequestV1 {
            opcode: WorkerOpcode::VerifyProofV1,
            request_id: 6,
            profile_id,
            payload: encode_verify_proof_payload(&kat.public_inputs, &bad_proof).unwrap(),
        })
        .unwrap();
    assert_eq!(invalid_proof.response.status, WorkerStatus::InvalidProof);
    assert!(!invalid_proof.terminate);

    let internal = runtime
        .dispatch(WorkerRequestV1 {
            opcode: WorkerOpcode::TreeRootV1,
            request_id: 7,
            profile_id,
            payload: encode_tree_root_payload(&[F::ZERO]).unwrap(),
        })
        .unwrap();
    assert_eq!(internal.response.status, WorkerStatus::InternalFailure);
    assert!(internal.terminate);

    let maximum = WorkerRequestV1 {
        opcode: WorkerOpcode::Profile,
        request_id: 1,
        profile_id,
        payload: vec![0; MAX_WORKER_FRAME_BYTES - 56],
    };
    assert_eq!(maximum.encode_frame().unwrap().len(), MAX_WORKER_FRAME_BYTES + 4);
    let oversized = WorkerRequestV1 { payload: vec![0; MAX_WORKER_FRAME_BYTES - 55], ..maximum };
    assert!(oversized.encode_frame().is_err());
}

#[test]
fn request_ids_identity_payloads_and_capacity_are_fatal_boundaries() {
    let profile_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../profile");
    let mut runtime = WorkerRuntime::from_artifact_files(
        &profile_dir.join("profile-descriptor-v1.bin"),
        &profile_dir.join("kat-v1.bin"),
    ).unwrap();
    let profile_id = runtime.profile_id();
    let fixture = SyntheticFixture::one_note();
    let request = |request_id, profile_id, payload| WorkerRequestV1 {
        opcode: WorkerOpcode::TreeRootV1,
        request_id,
        profile_id,
        payload,
    };
    assert!(runtime.dispatch(request(2, profile_id, encode_tree_root_payload(&[]).unwrap())).is_err());

    assert!(runtime.dispatch(request(1, [0; 32], encode_tree_root_payload(&[]).unwrap())).is_err());

    let mut trailing = encode_tree_root_payload(&fixture.commitments).unwrap();
    trailing.push(0);
    assert!(runtime.dispatch(request(1, profile_id, trailing)).is_err());

    let leaves = (1..=16).map(F::from).collect::<Vec<_>>();
    assert!(encode_tree_root_payload(&leaves).is_ok());
    assert!(encode_tree_root_payload(&[F::ONE; 17]).is_err());

    let source = include_str!("../src/bin/shielded-verifier-worker.rs");
    assert!(!source.contains("WitnessV1"));
    assert!(!source.contains("ProvingProfile"));
    let _: Option<DispatchResult> = None;
}
