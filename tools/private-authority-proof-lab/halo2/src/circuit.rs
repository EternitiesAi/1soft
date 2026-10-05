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
pub struct AuthorityConfig {
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
pub struct AuthorityCircuit {
    pub assignment: Option<Assignment>,
}

impl AuthorityCircuit {
    pub fn new(assignment: Assignment) -> Self {
        Self {
            assignment: Some(assignment),
        }
    }
}

#[derive(Clone, Debug)]
struct MainChip {
    config: AuthorityConfig,
}

impl MainChip {
    fn new(config: AuthorityConfig) -> Self {
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
    config: &AuthorityConfig,
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

impl Circuit<F> for AuthorityCircuit {
    type Config = AuthorityConfig;
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

        AuthorityConfig {
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
        let mut p = Vec::new();
        for i in 0..crate::PUBLIC_COUNT {
            let c = chip.load_f(&mut l, a.map(|a| a.public[i]), "public field")?;
            chip.constrain_instance(&mut l, &c, i)?;
            p.push(c);
        }
        chip.assert_constant(&mut l, &p[0], F::ONE, "relation version")?;
        for c in &p[..19] {
            chip.nonzero(&mut l, c, "nonzero public field")?;
        }
        let raw = |i| a.and_then(|a| integer(a.public[i])).map(u128::from);
        for i in 14..18 {
            chip.range_check(&mut l, &p[i], raw(i), 64, "public integer")?;
        }
        chip.strict_greater_u64(&mut l, &p[16], &p[15], raw(16), raw(15), "interval")?;
        let nums = [
            a.map(|a| a.witness.parent_cap),
            a.map(|a| a.witness.parent_spent),
            a.map(|a| a.witness.parent_version),
            a.map(|a| a.witness.grant_cap),
            a.map(|a| a.witness.grant_spent),
            a.map(|a| a.witness.grant_version),
            a.map(|a| a.witness.grant_expiry),
            a.map(|a| a.witness.payment),
        ];
        let mut n = Vec::new();
        for num in nums {
            let c = chip.load_u(&mut l, num.map(u128::from), "private integer")?;
            chip.range_check(&mut l, &c, num.map(u128::from), 64, "private integer range")?;
            n.push(c);
        }
        chip.nonzero(&mut l, &n[7], "positive payment")?;
        let expiry = chip.sub(&mut l, &n[6], &p[16], "grant expiry")?;
        let eraw = a
            .and_then(|a| a.witness.grant_expiry.checked_sub(integer(a.public[16])?))
            .map(u128::from);
        chip.range_check(&mut l, &expiry, eraw, 64, "grant expiry range")?;
        let fs = [
            a.map(|a| a.witness.parent_blind),
            a.map(|a| a.witness.parent_next_blind),
            a.map(|a| a.witness.grant_blind),
            a.map(|a| a.witness.grant_next_blind),
            a.map(|a| a.witness.agent_secret),
            a.map(|a| a.witness.recipient),
            a.map(|a| a.witness.payment_blind),
        ];
        let mut f = Vec::new();
        for value in fs {
            let c = chip.load_f(&mut l, value, "private field")?;
            chip.nonzero(&mut l, &c, "nonzero private field")?;
            f.push(c);
        }
        let zero = chip.load_constant(&mut l, F::ZERO, "zero")?;
        let one = chip.load_constant(&mut l, F::ONE, "one")?;
        let mut successor = Vec::new();
        for (spent, cap, version) in [(1, 0, 2), (4, 3, 5)] {
            let next_raw = a.map(|a| {
                u128::from(if spent == 1 {
                    a.witness.parent_spent
                } else {
                    a.witness.grant_spent
                }) + u128::from(a.witness.payment)
                    + u128::from(integer(a.public[17]).unwrap_or(u64::MAX))
            });
            let next = chip.load_u(&mut l, next_raw, "successor spent")?;
            chip.range_check(&mut l, &next, next_raw, 64, "successor spent range")?;
            chip.add3(
                &mut l,
                &next,
                &n[spent],
                &n[7],
                &p[17],
                "fee inclusive successor",
            )?;
            let remain = chip.sub(&mut l, &n[cap], &next, "remaining cap")?;
            let remraw = nums[cap]
                .zip(next_raw)
                .and_then(|(cap, next)| u128::from(cap).checked_sub(next));
            chip.range_check(&mut l, &remain, remraw, 64, "remaining cap range")?;
            let vr = nums[version].map(|v| u128::from(v) + 1);
            let vnext = chip.load_u(&mut l, vr, "successor version")?;
            chip.range_check(&mut l, &vnext, vr, 64, "successor version range")?;
            chip.add3(
                &mut l,
                &vnext,
                &n[version],
                &one,
                &zero,
                "exact version increment",
            )?;
            successor.push((next, vnext));
        }
        let domain = |l: &mut _, number| chip.load_constant(l, F::from(number), "relation domain");
        let kd = domain(&mut l, 210)?;
        let key = poseidon_hash(&config, &mut l, [kd, f[4].clone()], "agent key")?;
        for next in [false, true] {
            let (ps, pv) = if next {
                (&successor[0].0, &successor[0].1)
            } else {
                (&n[1], &n[2])
            };
            let pd = domain(&mut l, 200)?;
            let pc = poseidon_hash(
                &config,
                &mut l,
                [
                    pd,
                    p[1].clone(),
                    p[2].clone(),
                    p[3].clone(),
                    p[5].clone(),
                    p[14].clone(),
                    n[0].clone(),
                    ps.clone(),
                    pv.clone(),
                    f[usize::from(next)].clone(),
                ],
                "parent fragment",
            )?;
            chip.assert_equal(
                &mut l,
                &pc,
                &p[if next { 9 } else { 7 }],
                "parent commitment",
            )?;
            let (gs, gv) = if next {
                (&successor[1].0, &successor[1].1)
            } else {
                (&n[4], &n[5])
            };
            let gd = domain(&mut l, 201)?;
            let gc = poseidon_hash(
                &config,
                &mut l,
                [
                    gd,
                    p[1].clone(),
                    p[2].clone(),
                    p[3].clone(),
                    p[5].clone(),
                    p[6].clone(),
                    p[14].clone(),
                    key.clone(),
                    f[5].clone(),
                    n[3].clone(),
                    gs.clone(),
                    gv.clone(),
                    n[6].clone(),
                    f[2 + usize::from(next)].clone(),
                ],
                "grant fragment",
            )?;
            chip.assert_equal(
                &mut l,
                &gc,
                &p[if next { 10 } else { 8 }],
                "grant commitment",
            )?;
        }
        for (d, old, id, ver, target) in [(203, 7, 5, 2, 11), (204, 8, 6, 5, 12)] {
            let nd = domain(&mut l, d)?;
            let nf = poseidon_hash(
                &config,
                &mut l,
                [
                    nd,
                    p[old].clone(),
                    p[id].clone(),
                    p[14].clone(),
                    n[ver].clone(),
                ],
                "fragment nullifier",
            )?;
            chip.assert_equal(&mut l, &nf, &p[target], "nullifier binding")?;
        }
        let payd = domain(&mut l, 202)?;
        let pc = poseidon_hash(
            &config,
            &mut l,
            [
                payd,
                p[1].clone(),
                p[2].clone(),
                p[3].clone(),
                p[18].clone(),
                f[5].clone(),
                n[7].clone(),
                f[6].clone(),
            ],
            "payment request commitment",
        )?;
        chip.assert_equal(&mut l, &pc, &p[13], "payment binding")?;
        let mut auth = Vec::new();
        auth.push(domain(&mut l, 205)?);
        auth.extend(p[..19].iter().cloned());
        let auth_fields: [AssignedCell<F, F>; crate::PUBLIC_COUNT] = auth.try_into().unwrap();
        let auth = poseidon_hash(&config, &mut l, auth_fields, "authorization digest")?;
        chip.assert_equal(&mut l, &auth, &p[19], "authorization binding")?;
        Ok(())
    }
}
