use ff::{Field, PrimeField};
use recipient_transfer::{fixtures, request, wire, F};
#[test]
fn closed_request_pins_network_and_canonical_ranges() {
    let a = fixtures::first([1; 32]);
    let raw = request::encode(&a, [1; 32]).unwrap();
    assert_eq!(raw.len(), 1160);
    assert!(request::decode(&raw).is_ok());
    for index in [0, 8, 40, 72, 104] {
        let mut b = raw.clone();
        b[index] ^= 1;
        assert!(request::decode(&b).is_err());
    }
    for raw in [&raw[..raw.len() - 1], &[raw.as_slice(), &[0]].concat()] {
        assert!(request::decode(raw).is_err());
    }
    let mut b = raw.clone();
    b[136..168].fill(255);
    assert!(request::decode(&b).is_err());
    let mut b = raw.clone();
    let o = 136 + (13 + 2) * 32;
    b[o..o + 32].copy_from_slice(&F::from_u128(1u128 << 64).to_repr());
    assert!(request::decode(&b).is_err());
    let mut bad = a.clone();
    bad.witness.position = 16;
    assert!(request::encode(&bad, [1; 32]).is_err());
    let mut bad = a;
    bad.witness.recipient_secret = F::ZERO;
    assert!(request::encode(&bad, [1; 32]).is_err());
}
#[test]
fn legacy_and_extra_wire_refused() {
    let a = fixtures::first([1; 32]);
    let raw = wire::encode(&a.public, &vec![0; recipient_transfer::PROOF_BYTES]).unwrap();
    assert!(wire::decode(&raw).is_ok());
    let mut b = raw.clone();
    b[..8].copy_from_slice(b"1SOTPY01");
    assert!(wire::decode(&b).is_err());
    let mut b = raw.clone();
    b[..8].copy_from_slice(b"1SRCP008");
    assert!(wire::decode(&b).is_err());
    assert!(wire::decode(&[raw.as_slice(), &[0]].concat()).is_err());
    let mut p = a.public;
    p[0] = F::from(7);
    assert!(wire::encode(&p, &vec![0; recipient_transfer::PROOF_BYTES]).is_err());
}
