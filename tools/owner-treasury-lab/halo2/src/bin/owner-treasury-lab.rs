//! Bounded local laboratory bridge, not a qualified consensus worker.
use ff::{Field, PrimeField};
use owner_treasury_lab::{
    context::{network_domain, owner_key_commitment},
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
        return owner_treasury_lab::fixtures::emit(std::path::Path::new(&args[2]));
    }
    if args.len() == 4 && (args[1] == "fixtures-domain" || args[1] == "fixtures-domain-custody") {
        let text = &args[3];
        if text.len() != 64 {
            return Err("fixture-domain-bound".into());
        }
        let mut raw = [0u8; 32];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)?;
        }
        let f = Option::<F>::from(F::from_repr(raw)).ok_or("fixture-domain-field")?;
        if args[1] == "fixtures-domain-custody" {
            return owner_treasury_lab::fixtures::emit_custody_domain(std::path::Path::new(&args[2]), f);
        }
        return owner_treasury_lab::fixtures::emit_domain(std::path::Path::new(&args[2]), f);
    }
    if args.len() != 2 {
        return Err("one lab operation required".into());
    }
    if args[1] == "identities" {
        let (params, vk) = Profile::new()?.identities()?;
        let hex = |raw: [u8; 32]| raw.iter().map(|b| format!("{b:02x}")).collect::<String>();
        println!(
            "{{\"parameter_sha256\":\"{}\",\"verifying_key_sha256\":\"{}\"}}",
            hex(params),
            hex(vk)
        );
        return Ok(());
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
            if f.len() != 18 {
                return Err("context-bound".into());
            }
            let mut v = [F::ZERO; 19];
            v[0] = F::from(520);
            v[1..].copy_from_slice(&f);
            io::stdout().write_all(hash(v).to_repr().as_ref())?;
        }
        "network-domain" => {
            let digest: [u8; 32] = raw.try_into().map_err(|_| "network-domain-bound")?;
            io::stdout().write_all(network_domain(digest).to_repr().as_ref())?;
        }
        "owner-key" => {
            let key: [u8; 32] = raw.try_into().map_err(|_| "owner-key-bound")?;
            io::stdout().write_all(owner_key_commitment(key).to_repr().as_ref())?;
        }
        "note-root" => {
            let (root, _) = tree(&fields(&raw)?)?;
            io::stdout().write_all(root.to_repr().as_ref())?;
        }
        _ => return Err("unknown lab operation".into()),
    }
    Ok(())
}
