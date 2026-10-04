use std::{io::{self, Read, Write}, process};

use shielded_consensus_halo2::development_client::{
    DevelopmentClientRequestV1, MAX_CLIENT_REQUEST_BYTES,
};

fn run() -> Result<(), String> {
    let mut input = Vec::with_capacity(MAX_CLIENT_REQUEST_BYTES + 1);
    io::stdin()
        .take((MAX_CLIENT_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|_| "request read failed".to_string())?;
    let request = DevelopmentClientRequestV1::decode(&input)
        .map_err(|_| "invalid request".to_string())?;
    let output = request
        .derive()
        .map_err(|_| "request derivation failed".to_string())?
        .encode()
        .map_err(|_| "response encoding failed".to_string())?;
    io::stdout()
        .write_all(&output)
        .map_err(|_| "response write failed".to_string())?;
    Ok(())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("shielded development client failed: {error}");
        process::exit(1);
    }
}
