//! Bounded private stdin; random prover entropy, public fixed wire, static errors.
use recipient_transfer::{proof::Profile, request, wire};
use std::io::{self, Read, Write};
fn run() -> Result<(), ()> {
    if std::env::args_os().len() != 1 {
        return Err(());
    }
    let mut raw = Vec::new();
    io::stdin()
        .take((request::BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .map_err(|_| ())?;
    let mut seed = [0; 32];
    let result = (|| {
        let a = request::decode(&raw).map_err(|_| ())?;
        std::fs::File::open("/dev/urandom")
            .map_err(|_| ())?
            .read_exact(&mut seed)
            .map_err(|_| ())?;
        let public = a.public;
        let proof = Profile::new()
            .map_err(|_| ())?
            .prove(a, seed)
            .map_err(|_| ())?;
        wire::encode(&public, &proof).map_err(|_| ())
    })();
    raw.fill(0);
    seed.fill(0);
    io::stdout().write_all(&result?).map_err(|_| ())
}
fn main() {
    if run().is_err() {
        eprintln!("P8 recipient prover refused");
        std::process::exit(1)
    }
}
