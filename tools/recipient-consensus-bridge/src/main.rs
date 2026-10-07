//! Public verifier operations only. This executable is not a prover or wallet.
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
        .take(4097)
        .read_to_end(&mut raw)
        .map_err(|_| ())?;
    if raw.len() > 4096 {
        return Err(());
    }
    let out = match args[1].as_str() {
        "identities" => {
            if !raw.is_empty() {
                return Err(());
            }
            let (p, v) = Verifier::inspect().map_err(|_| ())?;
            format!("{{\"parameter_sha256\":\"{p}\",\"verifying_key_sha256\":\"{v}\"}}\n")
                .into_bytes()
        }
        "network-domain" => {
            let bootstrap: [u8; 32] = raw.try_into().map_err(|_| ())?;
            relation::network(bootstrap).to_repr().as_ref().to_vec()
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
        "verify" => {
            if raw.len() != 32 + wire::BYTES {
                return io::stdout().write_all(b"INVALID\n").map_err(|_| ());
            }
            let expected = Option::<F>::from(F::from_repr(raw[..32].try_into().map_err(|_| ())?));
            match wire::decode(&raw[32..]) {
                Ok((p, proof)) if expected == Some(p[1]) && p[1] != F::ZERO => {
                    let verifier = Verifier::new().map_err(|_| ())?;
                    if verifier.verify(&p, proof).is_ok() {
                        b"OK\n".to_vec()
                    } else {
                        b"INVALID\n".to_vec()
                    }
                }
                _ => b"INVALID\n".to_vec(),
            }
        }
        "startup" => {
            // Same bounded request and exact corruption as the legacy caller.
            // One ephemeral verifier independently checks both proofs, then
            // hashes its actual parameters/key. Nothing survives this process.
            if raw.len() != 32 + wire::BYTES {
                return Err(());
            }
            let expected = Option::<F>::from(F::from_repr(raw[..32].try_into().map_err(|_| ())?));
            let (p, proof) = wire::decode(&raw[32..]).map_err(|_| ())?;
            if expected != Some(p[1]) || p[1] == F::ZERO {
                return Err(());
            }
            let verifier = Verifier::new().map_err(|_| ())?;
            let valid = verifier.verify(&p, proof).is_ok();
            let mut bad = raw[32..].to_vec();
            *bad.last_mut().ok_or(())? ^= 1;
            let (bad_p, bad_proof) = wire::decode(&bad).map_err(|_| ())?;
            let corrupt = verifier.verify(&bad_p, bad_proof).is_ok();
            let (parameter, key) = verifier.identities().map_err(|_| ())?;
            format!("{{\"valid\":{valid},\"corrupt\":{corrupt},\"parameter_sha256\":\"{parameter}\",\"verifying_key_sha256\":\"{key}\"}}\n").into_bytes()
        }
        _ => return Err(()),
    };
    io::stdout().write_all(&out).map_err(|_| ())
}
fn main() {
    if run().is_err() {
        eprintln!("P8 consensus verifier unavailable");
        std::process::exit(2);
    }
}
