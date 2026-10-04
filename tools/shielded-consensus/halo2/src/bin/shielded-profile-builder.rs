use std::{env, path::PathBuf, process};

use shielded_consensus_halo2::profile::GeneratedProfile;

fn run() -> Result<(), String> {
    let mut arguments = env::args_os();
    let _program = arguments.next();
    let output = arguments
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../profile"));
    if arguments.next().is_some() {
        return Err("usage: shielded-profile-builder [OUTPUT_DIRECTORY]".to_string());
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| "crate has no shielded-consensus parent".to_string())?
        .to_path_buf();
    GeneratedProfile::build(&root)?.write_to(&output)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("shielded profile builder failed: {error}");
        process::exit(1);
    }
}
