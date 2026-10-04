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

use crate::fixture::{Assignment, F};

pub const DEPTH: usize = 4;
pub const K: u32 = 13;
pub const CIRCUIT_ID: &str = "1soft/privacy-proof-benchmark/halo2-pasta/v1";
pub const PUBLIC_INPUTS: [&str; 14] = [
    "version",
    "genesis",
    "asset",
    "context",
    "epoch",
    "height",
    "expiry",
    "policy",
    "root",
    "nullifier",
    "output_commitment_0",
    "output_commitment_1",
    "fee",
    "authorization_digest",
];

const WIDTH: usize = 3;
const RATE: usize = 2;

#[derive(Clone, Debug)]
pub struct NoteConfig {
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
pub struct NoteCircuit {
    pub assignment: Option<Assignment>,
}

impl NoteCircuit {
    pub fn new(assignment: Assignment) -> Self {
        Self {
            assignment: Some(assignment),
        }
    }
}

#[derive(Clone, Debug)]
struct MainChip {
    config: NoteConfig,
}

impl MainChip {
    fn new(config: NoteConfig) -> Self {
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
            |mut region| {
                region.assign_advice_from_constant(
                    || name,
                    self.config.main[0],
                    0,
                    value,
                )
            },
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
                difference.copy_advice(
                    || "difference",
                    &mut region,
                    self.config.main[2],
                    0,
                )?;
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
        let inverse = value.value().copied().map(|value| {
            Option::<F>::from(value.invert()).unwrap_or(F::ZERO)
        });
        layouter.assign_region(
            || name,
            |mut region| {
                self.config.q_nonzero.enable(&mut region, 0)?;
                value.copy_advice(|| "value", &mut region, self.config.main[0], 0)?;
                region.assign_advice(
                    || "inverse",
                    self.config.main[1],
                    0,
                    || inverse,
                )?;
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
                if_zero.copy_advice(
                    || "if zero",
                    &mut region,
                    self.config.main[1],
                    0,
                )?;
                if_one.copy_advice(
                    || "if one",
                    &mut region,
                    self.config.main[2],
                    0,
                )?;
                region.assign_advice(
                    || "selected",
                    self.config.main[3],
                    0,
                    || selected,
                )
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
                let first = value.copy_advice(
                    || "range value",
                    &mut region,
                    self.config.main[0],
                    0,
                )?;
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
    config: &NoteConfig,
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

impl Circuit<F> for NoteCircuit {
    type Config = NoteConfig;
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
        let poseidon = Pow5Chip::configure::<P128Pow5T3>(
            meta,
            state,
            partial_sbox,
            rc_a,
            rc_b,
        );

        NoteConfig {
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

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = MainChip::new(config.clone());
        let value = self.assignment.as_ref();

        let version = chip.load_u(&mut layouter, value.map(|v| v.version), "version")?;
        let genesis = chip.load_u(&mut layouter, value.map(|v| v.genesis), "genesis")?;
        let asset = chip.load_u(&mut layouter, value.map(|v| v.asset), "asset")?;
        let context = chip.load_u(&mut layouter, value.map(|v| v.context), "context")?;
        let epoch = chip.load_u(&mut layouter, value.map(|v| v.epoch), "epoch")?;
        let height = chip.load_u(&mut layouter, value.map(|v| v.height), "height")?;
        let expiry = chip.load_u(&mut layouter, value.map(|v| v.expiry), "expiry")?;
        let policy = chip.load_u(&mut layouter, value.map(|v| v.policy), "policy")?;
        let root = chip.load_f(&mut layouter, value.map(|v| v.root), "root")?;
        let nullifier =
            chip.load_f(&mut layouter, value.map(|v| v.nullifier), "nullifier")?;
        let output0 = chip.load_f(&mut layouter, value.map(|v| v.output0), "output 0")?;
        let output1 = chip.load_f(&mut layouter, value.map(|v| v.output1), "output 1")?;
        let fee = chip.load_u(&mut layouter, value.map(|v| v.fee), "fee")?;
        let authorization = chip.load_f(
            &mut layouter,
            value.map(|v| v.authorization),
            "authorization",
        )?;

        let public = [
            &version,
            &genesis,
            &asset,
            &context,
            &epoch,
            &height,
            &expiry,
            &policy,
            &root,
            &nullifier,
            &output0,
            &output1,
            &fee,
            &authorization,
        ];
        for (index, cell) in public.into_iter().enumerate() {
            chip.constrain_instance(&mut layouter, cell, index)?;
        }

        let position =
            chip.load_u(&mut layouter, value.map(|v| v.position), "position")?;
        let input_value =
            chip.load_u(&mut layouter, value.map(|v| v.value), "input value")?;
        let input_expiry = chip.load_u(
            &mut layouter,
            value.map(|v| v.input_expiry),
            "input expiry",
        )?;
        let input_blinding = chip.load_u(
            &mut layouter,
            value.map(|v| v.input_blinding),
            "input blinding",
        )?;
        let spend_secret = chip.load_u(
            &mut layouter,
            value.map(|v| v.spend_secret),
            "spend secret",
        )?;
        let note_secret = chip.load_u(
            &mut layouter,
            value.map(|v| v.note_secret),
            "note secret",
        )?;
        let mut path = Vec::with_capacity(DEPTH);
        for index in 0..DEPTH {
            path.push(chip.load_f(
                &mut layouter,
                value.map(|v| v.path[index]),
                "Merkle sibling",
            )?);
        }

        let output_value0 = chip.load_u(
            &mut layouter,
            value.map(|v| v.output_value0),
            "output value 0",
        )?;
        let output_value1 = chip.load_u(
            &mut layouter,
            value.map(|v| v.output_value1),
            "output value 1",
        )?;
        let output_expiry0 = chip.load_u(
            &mut layouter,
            value.map(|v| v.output_expiry0),
            "output expiry 0",
        )?;
        let output_expiry1 = chip.load_u(
            &mut layouter,
            value.map(|v| v.output_expiry1),
            "output expiry 1",
        )?;
        let output_key0 = chip.load_f(
            &mut layouter,
            value.map(|v| v.output_key0),
            "output key 0",
        )?;
        let output_key1 = chip.load_f(
            &mut layouter,
            value.map(|v| v.output_key1),
            "output key 1",
        )?;
        let blind0 =
            chip.load_u(&mut layouter, value.map(|v| v.blind0), "blind 0")?;
        let blind1 =
            chip.load_u(&mut layouter, value.map(|v| v.blind1), "blind 1")?;
        let output_note0 = chip.load_u(
            &mut layouter,
            value.map(|v| v.output_note0),
            "output note 0",
        )?;
        let output_note1 = chip.load_u(
            &mut layouter,
            value.map(|v| v.output_note1),
            "output note 1",
        )?;

        chip.assert_constant(&mut layouter, &version, F::ONE, "version is one")?;
        chip.range_check(
            &mut layouter,
            &version,
            value.map(|v| v.version),
            64,
            "version range",
        )?;
        chip.range_check(
            &mut layouter,
            &epoch,
            value.map(|v| v.epoch),
            64,
            "epoch range",
        )?;
        chip.range_check(
            &mut layouter,
            &height,
            value.map(|v| v.height),
            64,
            "height range",
        )?;
        chip.range_check(
            &mut layouter,
            &expiry,
            value.map(|v| v.expiry),
            64,
            "expiry range",
        )?;
        chip.range_check(
            &mut layouter,
            &position,
            value.map(|v| v.position),
            64,
            "position range",
        )?;
        let position_bits = chip.range_check(
            &mut layouter,
            &position,
            value.map(|v| v.position),
            DEPTH,
            "position depth range",
        )?;
        for (cell, raw, name) in [
            (&input_value, value.map(|v| v.value), "input value range"),
            (
                &input_expiry,
                value.map(|v| v.input_expiry),
                "input expiry range",
            ),
            (
                &output_value0,
                value.map(|v| v.output_value0),
                "output value 0 range",
            ),
            (
                &output_value1,
                value.map(|v| v.output_value1),
                "output value 1 range",
            ),
            (
                &output_expiry0,
                value.map(|v| v.output_expiry0),
                "output expiry 0 range",
            ),
            (
                &output_expiry1,
                value.map(|v| v.output_expiry1),
                "output expiry 1 range",
            ),
            (&fee, value.map(|v| v.fee), "fee range"),
        ] {
            chip.range_check(&mut layouter, cell, raw, 64, name)?;
        }

        chip.strict_greater_u64(
            &mut layouter,
            &expiry,
            &height,
            value.map(|v| v.expiry),
            value.map(|v| v.height),
            "transaction expiry ordering",
        )?;
        chip.strict_greater_u64(
            &mut layouter,
            &input_expiry,
            &height,
            value.map(|v| v.input_expiry),
            value.map(|v| v.height),
            "input expiry ordering",
        )?;
        chip.strict_greater_u64(
            &mut layouter,
            &output_expiry0,
            &height,
            value.map(|v| v.output_expiry0),
            value.map(|v| v.height),
            "output expiry 0 ordering",
        )?;
        chip.strict_greater_u64(
            &mut layouter,
            &output_expiry1,
            &height,
            value.map(|v| v.output_expiry1),
            value.map(|v| v.height),
            "output expiry 1 ordering",
        )?;
        chip.nonzero(&mut layouter, &input_value, "positive input value")?;
        chip.nonzero(&mut layouter, &output_value0, "positive output value 0")?;
        chip.nonzero(&mut layouter, &output_value1, "positive output value 1")?;
        chip.add3(
            &mut layouter,
            &input_value,
            &output_value0,
            &output_value1,
            &fee,
            "fee-inclusive conservation",
        )?;

        let domain100 = chip.load_constant(&mut layouter, F::from(100), "domain 100")?;
        let domain101 = chip.load_constant(&mut layouter, F::from(101), "domain 101")?;
        let domain102 = chip.load_constant(&mut layouter, F::from(102), "domain 102")?;
        let domain103 = chip.load_constant(&mut layouter, F::from(103), "domain 103")?;
        let domain105 = chip.load_constant(&mut layouter, F::from(105), "domain 105")?;
        let domain106 = chip.load_constant(&mut layouter, F::from(106), "domain 106")?;

        let spend_key = poseidon_hash(
            &config,
            &mut layouter,
            [domain106, spend_secret.clone()],
            "spend key hash",
        )?;
        let input_commitment = poseidon_hash(
            &config,
            &mut layouter,
            [
                domain100.clone(),
                version.clone(),
                genesis.clone(),
                asset.clone(),
                context.clone(),
                epoch.clone(),
                policy.clone(),
                input_expiry.clone(),
                input_value.clone(),
                spend_key,
                note_secret.clone(),
                input_blinding,
            ],
            "input note commitment",
        )?;
        let mut current = poseidon_hash(
            &config,
            &mut layouter,
            [domain101, input_commitment.clone()],
            "input leaf",
        )?;
        for level in 0..DEPTH {
            let left = chip.select(
                &mut layouter,
                &position_bits[level],
                &current,
                &path[level],
                "Merkle left select",
            )?;
            let right = chip.select(
                &mut layouter,
                &position_bits[level],
                &path[level],
                &current,
                "Merkle right select",
            )?;
            current = poseidon_hash(
                &config,
                &mut layouter,
                [domain102.clone(), left, right],
                "Merkle parent",
            )?;
        }
        chip.assert_equal(&mut layouter, &current, &root, "accepted root")?;

        let derived_nullifier = poseidon_hash(
            &config,
            &mut layouter,
            [
                domain103,
                version.clone(),
                genesis.clone(),
                asset.clone(),
                epoch.clone(),
                policy.clone(),
                context.clone(),
                spend_secret,
                note_secret,
                input_commitment,
                position,
            ],
            "nullifier",
        )?;
        chip.assert_equal(
            &mut layouter,
            &derived_nullifier,
            &nullifier,
            "public nullifier",
        )?;

        let derived_output0 = poseidon_hash(
            &config,
            &mut layouter,
            [
                domain100.clone(),
                version.clone(),
                genesis.clone(),
                asset.clone(),
                context.clone(),
                epoch.clone(),
                policy.clone(),
                output_expiry0,
                output_value0,
                output_key0,
                output_note0,
                blind0,
            ],
            "output commitment 0",
        )?;
        chip.assert_equal(
            &mut layouter,
            &derived_output0,
            &output0,
            "public output commitment 0",
        )?;
        let derived_output1 = poseidon_hash(
            &config,
            &mut layouter,
            [
                domain100,
                version.clone(),
                genesis.clone(),
                asset.clone(),
                context.clone(),
                epoch.clone(),
                policy.clone(),
                output_expiry1,
                output_value1,
                output_key1,
                output_note1,
                blind1,
            ],
            "output commitment 1",
        )?;
        chip.assert_equal(
            &mut layouter,
            &derived_output1,
            &output1,
            "public output commitment 1",
        )?;
        let output_difference =
            chip.sub(&mut layouter, &output0, &output1, "output difference")?;
        chip.nonzero(
            &mut layouter,
            &output_difference,
            "distinct output commitments",
        )?;

        let derived_authorization = poseidon_hash(
            &config,
            &mut layouter,
            [
                domain105,
                version,
                genesis,
                asset,
                context,
                epoch,
                height,
                expiry,
                policy,
                root,
                nullifier,
                output0,
                output1,
                fee,
            ],
            "authorization digest",
        )?;
        chip.assert_equal(
            &mut layouter,
            &derived_authorization,
            &authorization,
            "public authorization",
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::dev::MockProver;

    use super::*;

    fn verify(assignment: Assignment) -> Result<(), Vec<halo2_proofs::dev::VerifyFailure>> {
        let instances = assignment.public_inputs();
        MockProver::run(K, &NoteCircuit::new(assignment), vec![instances])
            .expect("circuit synthesis")
            .verify()
    }

    #[test]
    fn native_poseidon_fixture_matches_circuit() {
        assert_eq!(verify(Assignment::synthetic()), Ok(()));
    }

    #[test]
    fn output_opening_can_become_input() {
        let assignment = Assignment::synthetic().output_zero_as_future_input();
        assert_eq!(verify(assignment), Ok(()));
    }

    #[test]
    fn wrong_spend_secret_is_rejected() {
        assert!(verify(Assignment::synthetic().wrong_spend_secret()).is_err());
    }

    #[test]
    fn duplicate_output_opening_is_rejected() {
        assert!(verify(Assignment::synthetic().duplicate_outputs()).is_err());
    }

    #[test]
    fn all_constraint_mutations_are_rejected() {
        let valid = Assignment::synthetic();
        for assignment in [
            valid.invalid_membership(),
            valid.invalid_nullifier(),
            valid.invalid_output_commitment(),
            valid.invalid_fee_conservation(),
            valid.out_of_range_value(),
            valid.changed_authorization(),
        ] {
            assert!(verify(assignment).is_err());
        }
    }

    #[test]
    fn public_instance_order_is_frozen() {
        assert_eq!(PUBLIC_INPUTS.len(), 14);
        let assignment = Assignment::synthetic();
        let public = assignment.public_inputs();
        assert_eq!(public[0], F::ONE);
        assert_eq!(public[1], F::from(11));
        assert_eq!(public[12], F::ONE);
        assert_eq!(public[13], assignment.authorization);
    }
}
