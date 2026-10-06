//! Publicly documented synthetic fixtures; not key provisioning or arbitrary proving.
use ff::PrimeField;
use recipient_transfer::{fixtures, relation, request};
use std::io::{self, Read, Write};
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2
        || !matches!(
            args[1].as_str(),
            "first" | "second" | "competing" | "genesis-note"
        )
    {
        return Err("fixture operation".into());
    }
    let mut raw = Vec::new();
    io::stdin().take(33).read_to_end(&mut raw)?;
    let bootstrap: [u8; 32] = raw.try_into().map_err(|_| "bootstrap bound")?;
    let a = fixtures::first(bootstrap);
    if args[1] == "genesis-note" {
        io::stdout().write_all(relation::input(&a).to_repr().as_ref())?;
        return Ok(());
    }
    let assignment = if args[1] == "competing" {
        let mut competing = a;
        competing.public[6] = recipient_transfer::F::from(23);
        relation::derive(&mut competing);
        competing
    } else if args[1] == "first" {
        a
    } else {
        fixtures::second(&a)
    };
    let mut out = request::encode(&assignment, bootstrap)?;
    let result = io::stdout().write_all(&out);
    out.fill(0);
    result?;
    Ok(())
}
