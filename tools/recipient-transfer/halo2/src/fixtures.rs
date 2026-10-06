//! Explicit synthetic developer fixtures, never recipient key provisioning.
use crate::{
    relation::{self as r, Assignment, Witness},
    F,
};
use ff::Field;
pub fn first(bootstrap: [u8; 32]) -> Assignment {
    let mut p = [F::ZERO; 13];
    p[0] = F::from(8);
    p[1] = r::network(bootstrap);
    p[2] = F::from(2);
    p[3] = F::from(3);
    p[6] = F::from(21);
    p[7] = F::from(2);
    p[8] = F::from(8);
    p[9] = F::from(1);
    let w = Witness {
        recipient_secret: F::from(31),
        input_origin: F::from(111),
        input_value: 20,
        input_expiry: 64,
        input_secret: F::from(32),
        input_blind: F::from(33),
        position: 0,
        path: [F::ZERO; 4],
        destination: r::key(F::from(41)),
        payment: 12,
        payment_expiry: 60,
        payment_secret: F::from(42),
        payment_blind: F::from(43),
        change: 7,
        change_secret: F::from(34),
        change_blind: F::from(35),
    };
    let mut a = Assignment {
        public: p,
        witness: w,
    };
    a.witness.path = r::tree(&[r::input(&a)]).unwrap().1[0];
    r::derive(&mut a);
    a
}
pub fn second(a: &Assignment) -> Assignment {
    let mut b = a.clone();
    b.public[6] = F::from(22);
    b.witness = Witness {
        recipient_secret: F::from(41),
        input_origin: r::origin(a),
        input_value: 12,
        input_expiry: 60,
        input_secret: F::from(42),
        input_blind: F::from(43),
        position: 1,
        path: [F::ZERO; 4],
        destination: r::key(F::from(51)),
        payment: 5,
        payment_expiry: 55,
        payment_secret: F::from(52),
        payment_blind: F::from(53),
        change: 6,
        change_secret: F::from(44),
        change_blind: F::from(45),
    };
    b.witness.path = r::tree(&[r::input(a), a.public[10], a.public[11]])
        .unwrap()
        .1[1];
    r::derive(&mut b);
    b
}
