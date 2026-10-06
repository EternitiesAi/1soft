use std::array;

use ff::{Field, PrimeField};
use halo2_gadgets::poseidon::{
    primitives::{ConstantLength, P128Pow5T3},
    Hash as CircuitHash, Pow5Chip, Pow5Config,
};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Instance, Selector,
    },
    poly::Rotation,
};

use crate::{
    relation::{integer, Assignment},
    F,
};

const WIDTH: usize = 3;
const RATE: usize = 2;

#[derive(Clone, Debug)]
pub struct TransferConfig {
    main: [Column<Advice>; 4],
    instance: Column<Instance>,
    q_add3: Selector,
    q_sub: Selector,
    q_diff_one: Selector,
    q_nonzero: Selector,
    q_select: Selector,
    q_range: Selector,
    poseidon: Pow5Config<F, WIDTH, RATE>,
}

#[derive(Clone, Debug, Default)]
pub struct TransferCircuit {
    pub assignment: Option<Assignment>,
}

impl TransferCircuit {
    pub fn new(assignment: Assignment) -> Self {
        Self {
            assignment: Some(assignment),
        }
    }
}

#[derive(Clone, Debug)]
struct MainChip {
    config: TransferConfig,
}

impl MainChip {
    fn new(config: TransferConfig) -> Self {
        Self { config }
    }

    fn load_f(
        &self,
        layouter: &mut impl Layouter<F>,
        value: Option<F>,
        name: &'static str,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || name,
            |mut region| {
                region.assign_advice(
                    || name,
                    self.config.main[0],
                    0,
                    || value.map(Value::known).unwrap_or_else(Value::unknown),
                )
            },
        )
    }

    fn load_u(
        &self,
        layouter: &mut impl Layouter<F>,
        value: Option<u128>,
        name: &'static str,
    ) -> Result<AssignedCell<F, F>, Error> {
        self.load_f(layouter, value.map(F::from_u128), name)
    }

    fn load_constant(
        &self,
        layouter: &mut impl Layouter<F>,
        value: F,
        name: &'static str,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || name,
            |mut region| region.assign_advice_from_constant(|| name, self.config.main[0], 0, value),
        )
    }

    fn constrain_instance(
        &self,
        layouter: &mut impl Layouter<F>,
        value: &AssignedCell<F, F>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(value.cell(), self.config.instance, row)
    }

    fn assert_equal(
        &self,
        layouter: &mut impl Layouter<F>,
        left: &AssignedCell<F, F>,
        right: &AssignedCell<F, F>,
        name: &'static str,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || name,
            |mut region| region.constrain_equal(left.cell(), right.cell()),
        )
    }

    fn assert_constant(
        &self,
        layouter: &mut impl Layouter<F>,
        value: &AssignedCell<F, F>,
        constant: F,
        name: &'static str,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || name,
            |mut region| region.constrain_constant(value.cell(), constant),
        )
    }

    fn add3(
        &self,
        layouter: &mut impl Layouter<F>,
        total: &AssignedCell<F, F>,
        a: &AssignedCell<F, F>,
        b: &AssignedCell<F, F>,
        c: &AssignedCell<F, F>,
        name: &'static str,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || name,
            |mut region| {
                self.config.q_add3.enable(&mut region, 0)?;
                total.copy_advice(|| "total", &mut region, self.config.main[0], 0)?;
                a.copy_advice(|| "a", &mut region, self.config.main[1], 0)?;
                b.copy_advice(|| "b", &mut region, self.config.main[2], 0)?;
                c.copy_advice(|| "c", &mut region, self.config.main[3], 0)?;
                Ok(())
            },
        )
    }

    fn sub(
        &self,
        layouter: &mut impl Layouter<F>,
        left: &AssignedCell<F, F>,
        right: &AssignedCell<F, F>,
        name: &'static str,
    ) -> Result<AssignedCell<F, F>, Error> {
        let result = left
            .value()
            .copied()
            .zip(right.value().copied())
            .map(|(left, right)| left - right);
        layouter.assign_region(
            || name,
            |mut region| {
                self.config.q_sub.enable(&mut region, 0)?;
                left.copy_advice(|| "left", &mut region, self.config.main[0], 0)?;
                right.copy_advice(|| "right", &mut region, self.config.main[1], 0)?;
                region.assign_advice(|| "difference", self.config.main[2], 0, || result)
            },
        )
    }

    fn strict_greater_u64(
        &self,
        layouter: &mut impl Layouter<F>,
        greater: &AssignedCell<F, F>,
        smaller: &AssignedCell<F, F>,
        greater_raw: Option<u128>,
        smaller_raw: Option<u128>,
        name: &'static str,
    ) -> Result<(), Error> {
        let difference_raw = match (greater_raw, smaller_raw) {
            (Some(greater), Some(smaller)) => greater.checked_sub(smaller + 1),
            _ => None,
        };
        let difference = self.load_u(layouter, difference_raw, name)?;
        layouter.assign_region(
            || name,
            |mut region| {
                self.config.q_diff_one.enable(&mut region, 0)?;
                greater.copy_advice(|| "greater", &mut region, self.config.main[0], 0)?;
                smaller.copy_advice(|| "smaller", &mut region, self.config.main[1], 0)?;
                difference.copy_advice(|| "difference", &mut region, self.config.main[2], 0)?;
                Ok(())
            },
        )?;
        self.range_check(layouter, &difference, difference_raw, 64, name)?;
        Ok(())
    }

    fn nonzero(
        &self,
        layouter: &mut impl Layouter<F>,
        value: &AssignedCell<F, F>,
        name: &'static str,
    ) -> Result<(), Error> {
        let inverse = value
            .value()
            .copied()
            .map(|value| Option::<F>::from(value.invert()).unwrap_or(F::ZERO));
        layouter.assign_region(
            || name,
            |mut region| {
                self.config.q_nonzero.enable(&mut region, 0)?;
                value.copy_advice(|| "value", &mut region, self.config.main[0], 0)?;
                region.assign_advice(|| "inverse", self.config.main[1], 0, || inverse)?;
                Ok(())
            },
        )
    }

    fn select(
        &self,
        layouter: &mut impl Layouter<F>,
        bit: &AssignedCell<F, F>,
        if_zero: &AssignedCell<F, F>,
        if_one: &AssignedCell<F, F>,
        name: &'static str,
    ) -> Result<AssignedCell<F, F>, Error> {
        let selected = bit
            .value()
            .copied()
            .zip(if_zero.value().copied())
            .zip(if_one.value().copied())
            .map(|((bit, zero), one)| zero + bit * (one - zero));
        layouter.assign_region(
            || name,
            |mut region| {
                self.config.q_select.enable(&mut region, 0)?;
                bit.copy_advice(|| "bit", &mut region, self.config.main[0], 0)?;
                if_zero.copy_advice(|| "if zero", &mut region, self.config.main[1], 0)?;
                if_one.copy_advice(|| "if one", &mut region, self.config.main[2], 0)?;
                region.assign_advice(|| "selected", self.config.main[3], 0, || selected)
            },
        )
    }

    fn range_check(
        &self,
        layouter: &mut impl Layouter<F>,
        value: &AssignedCell<F, F>,
        raw: Option<u128>,
        bits: usize,
        name: &'static str,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        layouter.assign_region(
            || name,
            |mut region: Region<'_, F>| {
                let mut result = Vec::with_capacity(bits);
                let first =
                    value.copy_advice(|| "range value", &mut region, self.config.main[0], 0)?;
                let mut final_running = first;
                for index in 0..bits {
                    self.config.q_range.enable(&mut region, index)?;
                    let bit_value = raw
                        .map(|value| F::from(((value >> index) & 1) as u64))
                        .map(Value::known)
                        .unwrap_or_else(Value::unknown);
                    let bit = region.assign_advice(
                        || "range bit",
                        self.config.main[1],
                        index,
                        || bit_value,
                    )?;
                    result.push(bit);
                    let running_value = raw
                        .map(|value| F::from_u128(value >> (index + 1)))
                        .map(Value::known)
                        .unwrap_or_else(Value::unknown);
                    final_running = region.assign_advice(
                        || "next running value",
                        self.config.main[0],
                        index + 1,
                        || running_value,
                    )?;
                }
                region.constrain_constant(final_running.cell(), F::ZERO)?;
                Ok(result)
            },
        )
    }
}

fn poseidon_hash<const L: usize>(
    config: &TransferConfig,
    layouter: &mut impl Layouter<F>,
    message: [AssignedCell<F, F>; L],
    name: &'static str,
) -> Result<AssignedCell<F, F>, Error> {
    let chip = Pow5Chip::construct(config.poseidon.clone());
    let hasher = CircuitHash::<
        F,
        Pow5Chip<F, WIDTH, RATE>,
        P128Pow5T3,
        ConstantLength<L>,
        WIDTH,
        RATE,
    >::init(chip, layouter.namespace(|| name))?;
    hasher.hash(layouter.namespace(|| name), message)
}

impl Circuit<F> for TransferCircuit {
    type Config = TransferConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self { assignment: None }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let main = array::from_fn(|_| meta.advice_column());
        for column in main {
            meta.enable_equality(column);
        }
        let instance = meta.instance_column();
        meta.enable_equality(instance);

        let q_add3 = meta.selector();
        meta.create_gate("exact three-term conservation", |meta| {
            let q = meta.query_selector(q_add3);
            let total = meta.query_advice(main[0], Rotation::cur());
            let a = meta.query_advice(main[1], Rotation::cur());
            let b = meta.query_advice(main[2], Rotation::cur());
            let c = meta.query_advice(main[3], Rotation::cur());
            vec![q * (total - a - b - c)]
        });

        let q_sub = meta.selector();
        meta.create_gate("subtraction", |meta| {
            let q = meta.query_selector(q_sub);
            let left = meta.query_advice(main[0], Rotation::cur());
            let right = meta.query_advice(main[1], Rotation::cur());
            let difference = meta.query_advice(main[2], Rotation::cur());
            vec![q * (left - right - difference)]
        });

        let q_diff_one = meta.selector();
        meta.create_gate("strict greater difference", |meta| {
            let q = meta.query_selector(q_diff_one);
            let greater = meta.query_advice(main[0], Rotation::cur());
            let smaller = meta.query_advice(main[1], Rotation::cur());
            let difference = meta.query_advice(main[2], Rotation::cur());
            vec![q * (greater - smaller - difference - Expression::Constant(F::ONE))]
        });

        let q_nonzero = meta.selector();
        meta.create_gate("nonzero", |meta| {
            let q = meta.query_selector(q_nonzero);
            let value = meta.query_advice(main[0], Rotation::cur());
            let inverse = meta.query_advice(main[1], Rotation::cur());
            vec![q * (value * inverse - Expression::Constant(F::ONE))]
        });

        let q_select = meta.selector();
        meta.create_gate("conditional select", |meta| {
            let q = meta.query_selector(q_select);
            let bit = meta.query_advice(main[0], Rotation::cur());
            let zero = meta.query_advice(main[1], Rotation::cur());
            let one = meta.query_advice(main[2], Rotation::cur());
            let selected = meta.query_advice(main[3], Rotation::cur());
            vec![
                q.clone() * (selected - zero.clone() - bit.clone() * (one - zero)),
                q * bit.clone() * (Expression::Constant(F::ONE) - bit),
            ]
        });

        let q_range = meta.selector();
        meta.create_gate("little-endian range decomposition", |meta| {
            let q = meta.query_selector(q_range);
            let running = meta.query_advice(main[0], Rotation::cur());
            let next = meta.query_advice(main[0], Rotation::next());
            let bit = meta.query_advice(main[1], Rotation::cur());
            vec![
                q.clone() * (running - bit.clone() - next * F::from(2)),
                q * bit.clone() * (Expression::Constant(F::ONE) - bit),
            ]
        });

        let state = array::from_fn(|_| meta.advice_column());
        let partial_sbox = meta.advice_column();
        let rc_a: [Column<Fixed>; WIDTH] = array::from_fn(|_| meta.fixed_column());
        let rc_b: [Column<Fixed>; WIDTH] = array::from_fn(|_| meta.fixed_column());
        meta.enable_constant(rc_b[0]);
        let poseidon = Pow5Chip::configure::<P128Pow5T3>(meta, state, partial_sbox, rc_a, rc_b);

        TransferConfig {
            main,
            instance,
            q_add3,
            q_sub,
            q_diff_one,
            q_nonzero,
            q_select,
            q_range,
            poseidon,
        }
    }

    fn synthesize(&self, config: Self::Config, mut l: impl Layouter<F>) -> Result<(), Error> {
        let chip = MainChip::new(config.clone());
        let a = self.assignment.as_ref();
        let w = a.map(|a| &a.witness);
        let mut p = Vec::new();
        for i in 0..crate::PUBLIC_COUNT {
            let c = chip.load_f(&mut l, a.map(|a| a.public[i]), "public")?;
            chip.constrain_instance(&mut l, &c, i)?;
            chip.nonzero(&mut l, &c, "public nonzero")?;
            p.push(c)
        }
        chip.assert_constant(&mut l, &p[0], F::from(8), "P8 version")?;
        for i in [7, 8, 9] {
            chip.range_check(
                &mut l,
                &p[i],
                a.and_then(|a| integer(a.public[i])).map(u128::from),
                64,
                "public u64",
            )?;
        }
        chip.strict_greater_u64(
            &mut l,
            &p[8],
            &p[7],
            a.and_then(|a| integer(a.public[8])).map(u128::from),
            a.and_then(|a| integer(a.public[7])).map(u128::from),
            "strict window",
        )?;
        let load_u = |l: &mut _, raw: Option<u64>, name| -> Result<_, Error> {
            let c = chip.load_u(l, raw.map(u128::from), name)?;
            chip.range_check(l, &c, raw.map(u128::from), 64, name)?;
            Ok(c)
        };
        let iv = load_u(&mut l, w.map(|w| w.input_value), "input value")?;
        let ie = load_u(&mut l, w.map(|w| w.input_expiry), "input expiry")?;
        let pv = load_u(&mut l, w.map(|w| w.payment), "payment value")?;
        let pe = load_u(&mut l, w.map(|w| w.payment_expiry), "payment expiry")?;
        let cv = load_u(&mut l, w.map(|w| w.change), "change value")?;
        for c in [&iv, &pv, &cv] {
            chip.nonzero(&mut l, c, "positive values")?;
        }
        chip.add3(&mut l, &iv, &pv, &cv, &p[9], "conservation")?;
        for (left, right, lr, rr) in [
            (
                &pe,
                &p[8],
                w.map(|w| w.payment_expiry),
                a.and_then(|a| integer(a.public[8])),
            ),
            (
                &ie,
                &pe,
                w.map(|w| w.input_expiry),
                w.map(|w| w.payment_expiry),
            ),
        ] {
            let diff = chip.sub(&mut l, left, right, "expiry difference")?;
            chip.range_check(
                &mut l,
                &diff,
                lr.zip(rr)
                    .and_then(|(x, y)| x.checked_sub(y))
                    .map(u128::from),
                64,
                "expiry bounds",
            )?;
        }
        let mut f = Vec::new();
        for raw in [
            w.map(|w| w.recipient_secret),
            w.map(|w| w.input_origin),
            w.map(|w| w.input_secret),
            w.map(|w| w.input_blind),
            w.map(|w| w.destination),
            w.map(|w| w.payment_secret),
            w.map(|w| w.payment_blind),
            w.map(|w| w.change_secret),
            w.map(|w| w.change_blind),
        ] {
            let c = chip.load_f(&mut l, raw, "opening")?;
            chip.nonzero(&mut l, &c, "opening nonzero")?;
            f.push(c);
        }
        let domain = |l: &mut _, v: u64| chip.load_constant(l, F::from(v), "domain");
        let d1 = domain(&mut l, 810)?;
        let key = poseidon_hash(&config, &mut l, [d1, f[0].clone()], "recipient key")?;
        chip.nonzero(&mut l, &key, "recipient key nonzero")?;
        let d2 = domain(&mut l, 811)?;
        let input = poseidon_hash(
            &config,
            &mut l,
            [
                d2,
                p[1].clone(),
                p[2].clone(),
                p[3].clone(),
                f[1].clone(),
                ie.clone(),
                iv,
                key.clone(),
                f[2].clone(),
                f[3].clone(),
            ],
            "typed input",
        )?;
        chip.nonzero(&mut l, &input, "input commitment")?;
        let posraw = w.map(|w| u128::from(w.position));
        let pos = chip.load_u(&mut l, posraw, "position")?;
        let bits = chip.range_check(&mut l, &pos, posraw, 4, "position bits")?;
        let d3 = domain(&mut l, 812)?;
        let mut current = poseidon_hash(&config, &mut l, [d3, input.clone()], "leaf")?;
        for d in 0..4 {
            let sibling = chip.load_f(&mut l, w.map(|w| w.path[d]), "sibling")?;
            let left = chip.select(&mut l, &bits[d], &current, &sibling, "left")?;
            let right = chip.select(&mut l, &bits[d], &sibling, &current, "right")?;
            let d4 = domain(&mut l, 813)?;
            current = poseidon_hash(&config, &mut l, [d4, left, right], "branch")?;
        }
        chip.assert_equal(&mut l, &current, &p[4], "root binding")?;
        let d5 = domain(&mut l, 814)?;
        let nf = poseidon_hash(
            &config,
            &mut l,
            [
                d5,
                p[1].clone(),
                p[2].clone(),
                p[3].clone(),
                input,
                f[0].clone(),
            ],
            "stable nullifier",
        )?;
        chip.assert_equal(&mut l, &nf, &p[5], "nullifier binding")?;
        let d6 = domain(&mut l, 816)?;
        let origin = poseidon_hash(
            &config,
            &mut l,
            [d6, f[1].clone(), p[5].clone(), p[6].clone()],
            "successor origin",
        )?;
        chip.nonzero(&mut l, &origin, "nonzero origin")?;
        let d7 = domain(&mut l, 811)?;
        let pay = poseidon_hash(
            &config,
            &mut l,
            [
                d7,
                p[1].clone(),
                p[2].clone(),
                p[3].clone(),
                origin.clone(),
                pe,
                pv,
                f[4].clone(),
                f[5].clone(),
                f[6].clone(),
            ],
            "payment output",
        )?;
        let d8 = domain(&mut l, 811)?;
        let change = poseidon_hash(
            &config,
            &mut l,
            [
                d8,
                p[1].clone(),
                p[2].clone(),
                p[3].clone(),
                origin,
                ie,
                cv,
                key,
                f[7].clone(),
                f[8].clone(),
            ],
            "recipient change",
        )?;
        chip.assert_equal(&mut l, &pay, &p[10], "payment binding")?;
        chip.assert_equal(&mut l, &change, &p[11], "change binding")?;
        let diff = chip.sub(&mut l, &p[10], &p[11], "different outputs")?;
        chip.nonzero(&mut l, &diff, "distinct output commitments")?;
        let mut bound = vec![domain(&mut l, 815)?];
        bound.extend(p[..12].iter().cloned());
        let bound: [AssignedCell<F, F>; 13] = bound.try_into().unwrap();
        let digest = poseidon_hash(&config, &mut l, bound, "transaction binding")?;
        chip.assert_equal(&mut l, &digest, &p[12], "binding")?;
        Ok(())
    }
}
