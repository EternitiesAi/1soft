//! Explicit valueless synthetic fixture for long-height ledger qualification.
//! The existing circuit and wire remain unchanged. Never key provisioning.
use ff::PrimeField;
use recipient_transfer::{fixtures, relation as r, request, F};
use std::io::{self, Read, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 2 || !matches!(args[1].as_str(), "first" | "competing" | "genesis-note") {
        return Err("synthetic fixture operation".into());
    }
    let mut raw = Vec::new();
    io::stdin().take(33).read_to_end(&mut raw)?;
    let bootstrap: [u8; 32] = raw.try_into().map_err(|_| "bootstrap bound")?;
    let mut a = fixtures::first(bootstrap);
    a.witness.input_value = 1000;
    a.witness.input_expiry = 100000;
    a.witness.payment = 400;
    a.witness.payment_expiry = 100000;
    a.witness.change = 599;
    a.public[8] = F::from(100000);
    a.witness.path = r::tree(&[r::input(&a)])?.1[0];
    r::derive(&mut a);
    r::validate(&a)?;
    if args[1] == "genesis-note" {
        io::stdout().write_all(r::input(&a).to_repr().as_ref())?;
        return Ok(());
    }
    if args[1] == "competing" {
        a.public[6] = F::from(23);
        r::derive(&mut a);
    }
    let mut out = request::encode(&a, bootstrap)?;
    let result = io::stdout().write_all(&out);
    out.fill(0);
    result?;
    Ok(())
}
