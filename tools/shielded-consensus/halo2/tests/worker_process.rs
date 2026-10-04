#![cfg(feature = "worker")]

use std::{
    fs,
    io::{Read, Write},
    process::{Child, ChildStdout, Command, Stdio},
};

use shielded_consensus_halo2::{
    encoding::{WorkerOpcode, WorkerRequestV1, WorkerResponseV1, WorkerStatus},
    fixture::SyntheticFixture,
    profile::load_artifacts,
    worker_protocol::{
        decode_append_response, encode_tree_root_payload, encode_verify_append_payload,
        encode_verify_proof_payload,
    },
};

fn read_response(stdout: &mut ChildStdout) -> WorkerResponseV1 {
    let mut prefix = [0u8; 4];
    stdout.read_exact(&mut prefix).expect("read response prefix");
    let length = u32::from_le_bytes(prefix) as usize;
    let mut frame = Vec::with_capacity(4 + length);
    frame.extend_from_slice(&prefix);
    frame.resize(4 + length, 0);
    stdout.read_exact(&mut frame[4..]).expect("read response body");
    WorkerResponseV1::decode_frame(&frame).expect("decode response")
}

fn start_worker() -> Child {
    Command::new(env!("CARGO_BIN_EXE_shielded-verifier-worker"))
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn worker")
}

#[test]
fn worker_process_runs_startup_kat_is_single_threaded_and_emits_only_frames() {
    let profile = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../profile");
    let (descriptor, kat) = load_artifacts(&profile).unwrap();
    let profile_id = descriptor.identity();
    let fixture = SyntheticFixture::one_note();
    let mut child = start_worker();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();

    let requests = [
        WorkerRequestV1 { opcode: WorkerOpcode::Profile, request_id: 1, profile_id, payload: Vec::new() },
        WorkerRequestV1 { opcode: WorkerOpcode::TreeRootV1, request_id: 2, profile_id, payload: encode_tree_root_payload(&fixture.commitments).unwrap() },
        WorkerRequestV1 { opcode: WorkerOpcode::VerifyProofV1, request_id: 3, profile_id, payload: encode_verify_proof_payload(&kat.public_inputs, &kat.proof).unwrap() },
        WorkerRequestV1 { opcode: WorkerOpcode::VerifyAndAppendV1, request_id: 4, profile_id, payload: encode_verify_append_payload(&fixture.commitments, &kat.public_inputs, &kat.proof).unwrap() },
    ];
    let mut responses = Vec::new();
    for request in requests {
        stdin.write_all(&request.encode_frame().unwrap()).unwrap();
        stdin.flush().unwrap();
        responses.push(read_response(&mut stdout));
    }
    assert!(responses.iter().all(|response| response.status == WorkerStatus::Ok));
    assert_eq!(responses[0].payload, descriptor.encode().unwrap());
    assert_eq!(decode_append_response(&responses[3].payload).unwrap().position_0, 1);

    let status = fs::read_to_string(format!("/proc/{}/status", child.id())).unwrap();
    assert!(status.lines().any(|line| line == "Threads:\t1"));
    assert!(status.lines().any(|line| line == "NoNewPrivs:\t1"));
    assert!(status.lines().any(|line| line.starts_with("Seccomp:\t2")));
    let mut fds = fs::read_dir(format!("/proc/{}/fd", child.id()))
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    fds.sort();
    assert_eq!(fds, ["0", "1"]);

    drop(stdin);
    let mut remainder = Vec::new();
    stdout.read_to_end(&mut remainder).unwrap();
    assert!(remainder.is_empty(), "worker emitted unsolicited stdout bytes");
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
}


#[test]
fn worker_rejects_arguments_before_startup_and_terminates_after_internal_failure() {
    let rejected = Command::new(env!("CARGO_BIN_EXE_shielded-verifier-worker"))
        .arg("--profile")
        .output()
        .expect("run worker with forbidden argument");
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());

    let profile = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../profile");
    let (descriptor, _) = load_artifacts(&profile).unwrap();
    let mut child = start_worker();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let request = WorkerRequestV1 {
        opcode: WorkerOpcode::TreeRootV1,
        request_id: 1,
        profile_id: descriptor.identity(),
        payload: encode_tree_root_payload(&[shielded_consensus_halo2::field::F::from(0)]).unwrap(),
    };
    stdin.write_all(&request.encode_frame().unwrap()).unwrap();
    stdin.flush().unwrap();
    let response = read_response(&mut stdout);
    assert_eq!(response.status, WorkerStatus::InternalFailure);
    drop(stdin);
    let mut trailing = Vec::new();
    stdout.read_to_end(&mut trailing).unwrap();
    assert!(trailing.is_empty());
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
}
