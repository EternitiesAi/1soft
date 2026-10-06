//! Bounded private note derivation; emits only fixed binary data/static errors.
use std::io::{self, Read, Write};
fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().collect::<Vec<_>>();
    if args.len() != 2 {
        return Err("operation".into());
    }
    let mut raw = Vec::new();
    io::stdin().take(2603).read_to_end(&mut raw)?;
    let result = match args[1].as_str() {
        "derive" => owner_treasury_lab::note_request::derive(&raw),
        "construct" => owner_treasury_lab::note_request::construct(&raw),
        "merchant" => owner_treasury_lab::note_request::merchant(&raw),
        _ => Err("operation"),
    };
    raw.fill(0);
    io::stdout().write_all(&result?)?;
    Ok(())
}
fn main() {
    if run().is_err() {
        let _ = io::stderr().write_all(b"P7 note controller refused\n");
        std::process::exit(1);
    }
}
