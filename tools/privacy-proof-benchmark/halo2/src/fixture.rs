use ff::{Field, PrimeField};
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::pallas;

use crate::circuit::DEPTH;

pub type F = pallas::Base;
const WIDTH: usize = 3;
const RATE: usize = 2;

pub fn native_hash<const L: usize>(message: [F; L]) -> F {
    Hash::<F, P128Pow5T3, ConstantLength<L>, WIDTH, RATE>::init().hash(message)
}

fn f(value: u128) -> F {
    F::from_u128(value)
}

fn note_commitment(
    version: u128,
    genesis: u128,
    asset: u128,
    context: u128,
    epoch: u128,
    policy: u128,
    expiry: u128,
    value: u128,
    spend_key: F,
    note_secret: u128,
    blinding: u128,
) -> F {
    native_hash([
        f(100),
        f(version),
        f(genesis),
        f(asset),
        f(context),
        f(epoch),
        f(policy),
        f(expiry),
        f(value),
        spend_key,
        f(note_secret),
        f(blinding),
    ])
}

#[derive(Clone, Debug)]
pub struct Assignment {
    pub version: u128,
    pub genesis: u128,
    pub asset: u128,
    pub context: u128,
    pub epoch: u128,
    pub height: u128,
    pub expiry: u128,
    pub policy: u128,
    pub root: F,
    pub nullifier: F,
    pub output0: F,
    pub output1: F,
    pub fee: u128,
    pub authorization: F,

    pub position: u128,
    pub value: u128,
    pub input_expiry: u128,
    pub input_blinding: u128,
    pub spend_secret: u128,
    pub note_secret: u128,
    pub path: [F; DEPTH],

    pub output_value0: u128,
    pub output_value1: u128,
    pub output_expiry0: u128,
    pub output_expiry1: u128,
    pub output_key0: F,
    pub output_key1: F,
    pub blind0: u128,
    pub blind1: u128,
    pub output_note0: u128,
    pub output_note1: u128,
}

impl Assignment {
    pub fn synthetic() -> Self {
        let mut value = Self {
            version: 1,
            genesis: 11,
            asset: 12,
            context: 13,
            epoch: 2,
            height: 100,
            expiry: 200,
            policy: 14,
            root: F::ZERO,
            nullifier: F::ZERO,
            output0: F::ZERO,
            output1: F::ZERO,
            fee: 1,
            authorization: F::ZERO,
            position: 5,
            value: 100,
            input_expiry: 300,
            input_blinding: 21,
            spend_secret: 22,
            note_secret: 23,
            path: [F::ZERO; DEPTH],
            output_value0: 40,
            output_value1: 59,
            output_expiry0: 400,
            output_expiry1: 500,
            output_key0: native_hash([f(106), f(33)]),
            output_key1: native_hash([f(106), f(43)]),
            blind0: 32,
            blind1: 42,
            output_note0: 34,
            output_note1: 44,
        };
        value.rebuild_full_tree();
        value
    }

    pub fn public_inputs(&self) -> Vec<F> {
        vec![
            f(self.version),
            f(self.genesis),
            f(self.asset),
            f(self.context),
            f(self.epoch),
            f(self.height),
            f(self.expiry),
            f(self.policy),
            self.root,
            self.nullifier,
            self.output0,
            self.output1,
            f(self.fee),
            self.authorization,
        ]
    }

    pub fn canonical_public_bytes(&self) -> Vec<u8> {
        let mut output = Vec::with_capacity(14 * 32);
        for value in self.public_inputs() {
            output.extend_from_slice(value.to_repr().as_ref());
        }
        output
    }

    fn spend_key(&self) -> F {
        native_hash([f(106), f(self.spend_secret)])
    }

    fn input_commitment(&self) -> F {
        note_commitment(
            self.version,
            self.genesis,
            self.asset,
            self.context,
            self.epoch,
            self.policy,
            self.input_expiry,
            self.value,
            self.spend_key(),
            self.note_secret,
            self.input_blinding,
        )
    }

    fn rebuild_outputs_and_auth(&mut self, input: F) {
        self.nullifier = native_hash([
            f(103),
            f(self.version),
            f(self.genesis),
            f(self.asset),
            f(self.epoch),
            f(self.policy),
            f(self.context),
            f(self.spend_secret),
            f(self.note_secret),
            input,
            f(self.position),
        ]);
        self.output0 = note_commitment(
            self.version,
            self.genesis,
            self.asset,
            self.context,
            self.epoch,
            self.policy,
            self.output_expiry0,
            self.output_value0,
            self.output_key0,
            self.output_note0,
            self.blind0,
        );
        self.output1 = note_commitment(
            self.version,
            self.genesis,
            self.asset,
            self.context,
            self.epoch,
            self.policy,
            self.output_expiry1,
            self.output_value1,
            self.output_key1,
            self.output_note1,
            self.blind1,
        );
        self.refresh_authorization();
    }

    pub fn refresh_authorization(&mut self) {
        self.authorization = native_hash([
            f(105),
            f(self.version),
            f(self.genesis),
            f(self.asset),
            f(self.context),
            f(self.epoch),
            f(self.height),
            f(self.expiry),
            f(self.policy),
            self.root,
            self.nullifier,
            self.output0,
            self.output1,
            f(self.fee),
        ]);
    }

    pub fn rebuild_full_tree(&mut self) {
        let input = self.input_commitment();
        let mut nodes = Vec::with_capacity(1 << DEPTH);
        for index in 0..(1usize << DEPTH) {
            let commitment = if index == self.position as usize {
                input
            } else {
                note_commitment(
                    self.version,
                    self.genesis,
                    self.asset,
                    self.context,
                    self.epoch,
                    self.policy,
                    300,
                    10 + index as u128,
                    f(70 + index as u128),
                    90 + index as u128,
                    110 + index as u128,
                )
            };
            nodes.push(native_hash([f(101), commitment]));
        }
        let mut position = self.position as usize;
        for level in 0..DEPTH {
            self.path[level] = nodes[position ^ 1];
            let mut parents = Vec::with_capacity(nodes.len() / 2);
            for pair in nodes.chunks_exact(2) {
                parents.push(native_hash([f(102), pair[0], pair[1]]));
            }
            nodes = parents;
            position >>= 1;
        }
        self.root = nodes[0];
        self.rebuild_outputs_and_auth(input);
    }

    pub fn rebuild_from_existing_path(&mut self) {
        let input = self.input_commitment();
        let mut current = native_hash([f(101), input]);
        for level in 0..DEPTH {
            current = if ((self.position >> level) & 1) == 1 {
                native_hash([f(102), self.path[level], current])
            } else {
                native_hash([f(102), current, self.path[level]])
            };
        }
        self.root = current;
        self.rebuild_outputs_and_auth(input);
    }

    pub fn invalid_membership(&self) -> Self {
        let mut value = self.clone();
        value.path[0] += F::ONE;
        value
    }

    pub fn invalid_nullifier(&self) -> Self {
        let mut value = self.clone();
        value.nullifier += F::ONE;
        value.refresh_authorization();
        value
    }

    pub fn invalid_output_commitment(&self) -> Self {
        let mut value = self.clone();
        value.output0 += F::ONE;
        value.refresh_authorization();
        value
    }

    pub fn invalid_fee_conservation(&self) -> Self {
        let mut value = self.clone();
        value.fee = 2;
        value.refresh_authorization();
        value
    }

    pub fn out_of_range_value(&self) -> Self {
        let mut value = self.clone();
        value.value = 1u128 << 64;
        value.output_value0 = (1u128 << 64) - 2;
        value.output_value1 = 1;
        value.rebuild_from_existing_path();
        value
    }

    pub fn changed_authorization(&self) -> Self {
        let mut value = self.clone();
        value.authorization += F::ONE;
        value
    }

    pub fn wrong_spend_secret(&self) -> Self {
        let mut value = self.clone();
        value.spend_secret += 1;
        value
    }

    pub fn duplicate_outputs(&self) -> Self {
        let mut value = self.clone();
        value.output_value1 = value.output_value0;
        value.output_expiry1 = value.output_expiry0;
        value.output_key1 = value.output_key0;
        value.output_note1 = value.output_note0;
        value.blind1 = value.blind0;
        value.output1 = value.output0;
        value.value = value.output_value0 + value.output_value1 + value.fee;
        value.rebuild_full_tree();
        value
    }

    pub fn output_zero_as_future_input(&self) -> Self {
        let mut value = self.clone();
        value.height = 101;
        value.value = self.output_value0;
        value.input_expiry = self.output_expiry0;
        value.input_blinding = self.blind0;
        value.spend_secret = 33;
        value.note_secret = self.output_note0;
        value.output_value0 = 20;
        value.output_value1 = 19;
        value.rebuild_full_tree();
        value
    }
}
