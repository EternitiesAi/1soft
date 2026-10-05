//! Bounded local lab bridge. Not the hardened P5 verifier worker.
use ff::{Field, PrimeField};
use private_treasury_payment_lab::{
    proof::Profile,
    relation::tree,
    wire::{decode, fields},
    F,
};
use shielded_consensus_halo2::tree::native_hash as hash;
use std::io::{self, Read, Write};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() == 3 && args[1] == "fixtures" {
        return private_treasury_payment_lab::fixtures::emit(std::path::Path::new(&args[2]));
    }
    if args.len() != 2 {
        return Err("one operation required".into());
    }
    let mut raw = Vec::new();
    io::stdin().take(16385).read_to_end(&mut raw)?;
    if raw.len() > 16384 {
        return Err("input-bound".into());
    }
    match args[1].as_str() {
        "verify" => {
            let (p, proof) = decode(&raw)?;
            Profile::new()?.verify(&p, proof)?;
            io::stdout().write_all(b"verified\n")?;
        }
        "context-root" => {
            let f = fields(&raw)?;
            if f.len() != 10 {
                return Err("context-bound".into());
            }
            let mut v = [F::ZERO; 11];
            v[0] = F::from(420);
            v[1..].copy_from_slice(&f);
            io::stdout().write_all(hash(v).to_repr().as_ref())?;
        }
        "note-root" => {
            let f = fields(&raw)?;
            let (root, _) = tree(&f)?;
            io::stdout().write_all(root.to_repr().as_ref())?;
        }
        _ => return Err("operation".into()),
    }
    Ok(())
}
