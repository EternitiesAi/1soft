//! Private bounded projection of the frozen P8 relation. No network or custody.
use ff::{Field, PrimeField};
use recipient_transfer::{relation as r, request, F};
use std::io::{self, Read, Write};

fn run(op: &str, raw: &[u8]) -> Result<Vec<u8>, &'static str> {
    let f = |b: &[u8]| -> Result<F, &'static str> {
        Option::<F>::from(F::from_repr(b.try_into().map_err(|_| "field")?))
            .filter(|v| *v != F::ZERO).ok_or("field")
    };
    if op == "key" {
        if raw.len() != 32 { return Err("bound"); }
        return Ok(r::key(f(raw)?).to_repr().to_vec());
    }
    if !matches!(op, "inspect-note" | "construct") || raw.len() < 321 { return Err("operation"); }
    let bootstrap: [u8; 32] = raw[..32].try_into().unwrap();
    let fs = raw[32..288].chunks_exact(32).map(f).collect::<Result<Vec<_>, _>>()?;
    let count = raw[288] as usize;
    let base = 289 + count * 32;
    let expected = base + if op == "construct" { 352 } else { 0 };
    if !(1..=16).contains(&count) || raw.len() != expected { return Err("bound"); }
    let notes = raw[289..base].chunks_exact(32).map(f).collect::<Result<Vec<_>, _>>()?;
    let n = |v: F| r::integer(v).ok_or("integer");
    let mut a = r::Assignment {
        public: [F::ONE; 13],
        witness: r::Witness {
            recipient_secret: fs[7], input_origin: fs[2], input_value: n(fs[3])?,
            input_expiry: n(fs[4])?, input_secret: fs[5], input_blind: fs[6],
            position: 0, path: [F::ZERO; 4], destination: F::ONE, payment: 1,
            payment_expiry: 1, payment_secret: F::ONE, payment_blind: F::ONE,
            change: 1, change_secret: F::ONE, change_blind: F::ONE,
        },
    };
    a.public[0] = F::from(8); a.public[1] = r::network(bootstrap);
    a.public[2] = fs[0]; a.public[3] = fs[1];
    let input = r::input(&a);
    let position = notes.iter().position(|v| *v == input).ok_or("absent")?;
    let (root, paths) = r::tree(&notes)?;
    a.witness.position = position as u16; a.witness.path = paths[position];
    if op == "inspect-note" {
        let mut out = Vec::new();
        for v in [input, r::key(fs[7]), r::nullifier(&a), root] { out.extend(v.to_repr()); }
        out.extend((position as u16).to_le_bytes());
        for v in paths[position] { out.extend(v.to_repr()); }
        return Ok(out);
    }
    let v = raw[base..].chunks_exact(32).map(f).collect::<Result<Vec<_>, _>>()?;
    for (slot, value) in [(6,v[0]),(7,v[1]),(8,v[2]),(9,v[3])] { a.public[slot] = value; }
    a.witness.destination = v[4]; a.witness.payment = n(v[5])?;
    a.witness.payment_expiry = n(v[6])?; a.witness.payment_secret = v[7];
    a.witness.payment_blind = v[8]; a.witness.change_secret = v[9]; a.witness.change_blind = v[10];
    a.witness.change = a.witness.input_value.checked_sub(a.witness.payment)
        .and_then(|x| x.checked_sub(n(v[3]).ok()?)).filter(|x| *x > 0).ok_or("conservation")?;
    r::derive(&mut a); r::validate(&a)?;
    let mut out = request::encode(&a, bootstrap)?;
    out.extend(r::origin(&a).to_repr());
    Ok(out)
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let mut raw = Vec::new();
    let result = if args.len() == 2 && io::stdin().take(1154).read_to_end(&mut raw).is_ok() {
        run(&args[1], &raw)
    } else { Err("input") };
    raw.fill(0);
    match result {
        Ok(mut out) => { let ok = io::stdout().write_all(&out).is_ok(); out.fill(0); if !ok { std::process::exit(2); } }
        Err(_) => std::process::exit(2), // No private input or detailed diagnostic on stderr.
    }
}
