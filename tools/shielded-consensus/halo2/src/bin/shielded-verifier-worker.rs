use std::{env, io::{self, Read, Write}, process};

use shielded_consensus_halo2::{
    constants::MAX_WORKER_FRAME_BYTES,
    encoding::WorkerRequestV1,
    sandbox_linux::install_worker_sandbox,
    worker_protocol::WorkerRuntime,
};

const PROFILE_DESCRIPTOR: &[u8] = include_bytes!("../../../profile/profile-descriptor-v1.bin");
const KAT: &[u8] = include_bytes!("../../../profile/kat-v1.bin");

fn read_frame(input: &mut impl Read) -> Result<Option<Vec<u8>>, ()> {
    let mut prefix = [0u8; 4];
    loop {
        match input.read(&mut prefix[..1]) {
            Ok(0) => return Ok(None),
            Ok(1) => break,
            Ok(_) => return Err(()),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err(()),
        }
    }
    input.read_exact(&mut prefix[1..]).map_err(|_| ())?;
    let length = u32::from_le_bytes(prefix) as usize;
    if length > MAX_WORKER_FRAME_BYTES { return Err(()); }
    let mut frame = Vec::with_capacity(4 + length);
    frame.extend_from_slice(&prefix);
    frame.resize(4 + length, 0);
    input.read_exact(&mut frame[4..]).map_err(|_| ())?;
    Ok(Some(frame))
}

fn run_loop(mut runtime: WorkerRuntime) -> Result<(), ()> {
    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();
    while let Some(frame) = read_frame(&mut input)? {
        let request = WorkerRequestV1::decode_frame(&frame).map_err(|_| ())?;
        let dispatched = runtime.dispatch(request).map_err(|_| ())?;
        let response = dispatched.response.encode_frame().map_err(|_| ())?;
        output.write_all(&response).map_err(|_| ())?;
        output.flush().map_err(|_| ())?;
        if dispatched.terminate { return Err(()); }
    }
    Ok(())
}

fn main() {
    if env::args_os().len() != 1 {
        eprintln!("shielded verifier worker accepts no arguments");
        process::exit(1);
    }
    let runtime = match WorkerRuntime::from_artifact_bytes(PROFILE_DESCRIPTOR, KAT) {
        Ok(runtime) => runtime,
        Err(_) => {
            eprintln!("shielded verifier worker startup failed");
            process::exit(1);
        }
    };
    if install_worker_sandbox().is_err() {
        process::exit(1);
    }
    if run_loop(runtime).is_err() {
        process::exit(1);
    }
}
