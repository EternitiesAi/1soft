//! Known synthetic openings for finite validator tests; not key provisioning.
use ff::PrimeField;
use recipient_transfer::{fixtures, relation as r, request, F};
use std::io::{self, Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2
        || !matches!(
            args[1].as_str(),
            "first" | "second" | "competing" | "duplicate-intent" | "wrong-fee" | "genesis-note"
        )
    {
        return Err("synthetic fixture operation".into());
    }
    let mut raw = Vec::new();
    io::stdin().take(33).read_to_end(&mut raw)?;
    let bootstrap: [u8; 32] = raw.try_into().map_err(|_| "bootstrap bound")?;
    let mut first = fixtures::first(bootstrap);
    // Finite consensus windows, not a relaxation of the frozen expiry circuit.
    first.public[8] = F::from(32);
    r::derive(&mut first);
    if args[1] == "genesis-note" {
        io::stdout().write_all(r::input(&first).to_repr().as_ref())?;
        return Ok(());
    }
    let mut a = match args[1].as_str() {
        "second" | "duplicate-intent" => fixtures::second(&first),
        _ => first,
    };
    match args[1].as_str() {
        "competing" => a.public[6] = F::from(23),
        "duplicate-intent" => a.public[6] = F::from(21),
        "wrong-fee" => {
            a.public[9] = F::from(2);
            a.witness.change = 6;
        }
        _ => (),
    }
    r::derive(&mut a);
    let mut out = request::encode(&a, bootstrap)?;
    let result = io::stdout().write_all(&out);
    out.fill(0);
    result?;
    Ok(())
}
