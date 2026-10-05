//! One bounded stdin request -> one locally verified P7 wire. No fixture or network API.
use owner_treasury_lab::{proof::Profile, prover_request, wire};
use std::io::{self, Read, Write};

fn run() -> Result<(), ()> {
    if std::env::args_os().len() != 1 {
        return Err(());
    }
    let mut input = Vec::with_capacity(prover_request::BYTES + 1);
    io::stdin()
        .take((prover_request::BYTES + 1) as u64)
        .read_to_end(&mut input)
        .map_err(|_| ())?;
    let assignment = prover_request::decode(&input).map_err(|_| ())?;
    // Never accept a caller seed or use the deterministic fixture seed.
    let mut seed = [0; 32];
    std::fs::File::open("/dev/urandom")
        .map_err(|_| ())?
        .read_exact(&mut seed)
        .map_err(|_| ())?;
    let public = assignment.public;
    let profile = Profile::new().map_err(|_| ())?;
    let proof = profile.prove(assignment, seed).map_err(|_| ())?;
    let output = wire::encode(&public, &proof).map_err(|_| ())?;
    input.fill(0);
    seed.fill(0);
    io::stdout().write_all(&output).map_err(|_| ())
}
fn main() {
    if run().is_err() {
        // Static failure only; never interpolate private input or underlying errors.
        eprintln!("P7 development prover refused");
        std::process::exit(1);
    }
}
