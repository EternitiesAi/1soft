//! Verifier-only build excludes the private request parser, fixtures and prover.
use ff::{Field, PrimeField};
use recipient_transfer::{relation, verifier::Verifier, wire, F};
use std::io::{self, Read, Write};
fn run() -> Result<(), ()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 {
        return Err(());
    }
    let mut raw = Vec::new();
    io::stdin()
        .take((wire::BYTES + 33) as u64)
        .read_to_end(&mut raw)
        .map_err(|_| ())?;
    let out = match args[1].as_str() {
        "inspect" => {
            if !raw.is_empty() {
                return Err(());
            }
            let (p, v) = Verifier::inspect().map_err(|_| ())?;
            (format!(r#"{{"parameter_sha256":"{p}","verifying_key_sha256":"{v}"}}"#) + "\n")
                .into_bytes()
        }
        "verify" => {
            let verifier = Verifier::new().map_err(|_| ())?;
            if raw.len() != 32 + wire::BYTES {
                return io::stdout().write_all(b"INVALID\n").map_err(|_| ());
            }
            let expected = Option::<F>::from(F::from_repr(raw[..32].try_into().map_err(|_| ())?));
            match wire::decode(&raw[32..]) {
                Ok((p, proof))
                    if expected == Some(p[1])
                        && p[1] != F::ZERO
                        && verifier.verify(&p, proof).is_ok() =>
                {
                    b"OK\n".to_vec()
                }
                _ => b"INVALID\n".to_vec(),
            }
        }
        "note-root" => {
            if raw.is_empty() || raw.len() % 32 != 0 || raw.len() > 512 {
                return Err(());
            }
            let notes = raw
                .chunks_exact(32)
                .map(|b| Option::<F>::from(F::from_repr(b.try_into().unwrap())).ok_or(()))
                .collect::<Result<Vec<_>, _>>()?;
            relation::tree(&notes)
                .map_err(|_| ())?
                .0
                .to_repr()
                .as_ref()
                .to_vec()
        }
        _ => return Err(()),
    };
    io::stdout().write_all(&out).map_err(|_| ())
}
fn main() {
    if run().is_err() {
        eprintln!("P8 recipient verifier unavailable");
        std::process::exit(2);
    }
}
