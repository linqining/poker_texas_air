//! Non-native Curve25519 AIR cost model.
//!
//! This is intentionally an arithmetic-core benchmark, not a production
//! verifier. It compiles one extended-Edwards addition, and (for Ristretto)
//! the Ristretto encode/decode arithmetic, into real Stwo constraints over
//! M31. The inverse-square-root witnesses are constrained by `a * r² = 1`.
//! Field limbs are 8-bit values in 32 trace columns.
//!
//! Deliberately out of scope, and therefore not counted below: limb range and
//! top-limb checks, canonical input-byte checks, sign/conditional-selection
//! constraints, the Edwards input curve/subgroup checks, scalar multiplication,
//! DLEQ, and hash-to-group. A production implementation should add these with
//! M31 lookup tables plus boolean selectors; treat the reported measurements as
//! a lower bound only.

use std::time::Instant;

use num_bigint::BigUint;
use num_traits::{One, Zero};
use stwo::core::air::Component;
use stwo::core::channel::Poseidon252Channel;
use stwo::core::fields::m31::{M31, P as M31_MODULUS};
use stwo::core::fields::qm31::SecureField;
use stwo::core::fri::FriConfig;
use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
use stwo::core::poly::circle::CanonicCoset;
use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleChannel;
use stwo::core::verifier::verify;
use stwo::prover::backend::simd::SimdBackend;
use stwo::prover::backend::simd::column::BaseColumn;
use stwo::prover::pcs::CommitmentSchemeProver;
use stwo::prover::poly::BitReversedOrder;
use stwo::prover::poly::NaturalOrder;
use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
use stwo::prover::prove;
use stwo_constraint_framework::{
    EvalAtRow, FrameworkComponent, FrameworkEval, TraceLocationAllocator,
};

const LIMBS: usize = 32;
const RADIX: u64 = 256;
const LOG_SIZE: u32 = 4;
const P_BITS: usize = 255;

fn signed_m31(value: i64) -> M31 {
    M31::from(value.rem_euclid(i64::from(M31_MODULUS)) as u32)
}

fn modulus() -> BigUint {
    (BigUint::one() << P_BITS) - BigUint::from(19u32)
}

fn modulus_limbs() -> [u32; LIMBS] {
    let bytes = modulus().to_bytes_le();
    let mut out = [0u32; LIMBS];
    for (i, byte) in bytes.into_iter().enumerate().take(LIMBS) {
        out[i] = u32::from(byte);
    }
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Fp(BigUint);

impl Fp {
    fn new(value: BigUint) -> Self {
        Self(value % modulus())
    }

    fn from_decimal(value: &str) -> Self {
        Self::new(BigUint::parse_bytes(value.as_bytes(), 10).unwrap())
    }

    fn from_radix_51(limbs: [u64; 5]) -> Self {
        let value = limbs
            .into_iter()
            .enumerate()
            .fold(BigUint::zero(), |acc, (i, limb)| {
                acc + (BigUint::from(limb) << (51 * i))
            });
        Self::new(value)
    }

    fn zero() -> Self {
        Self(BigUint::zero())
    }

    fn one() -> Self {
        Self(BigUint::one())
    }

    fn add(&self, rhs: &Self) -> Self {
        Self::new(&self.0 + &rhs.0)
    }

    fn sub(&self, rhs: &Self) -> Self {
        if self.0 >= rhs.0 {
            Self(&self.0 - &rhs.0)
        } else {
            Self(&self.0 + modulus() - &rhs.0)
        }
    }

    fn neg(&self) -> Self {
        if self.0.is_zero() {
            Self::zero()
        } else {
            Self(&modulus() - &self.0)
        }
    }

    fn mul(&self, rhs: &Self) -> Self {
        Self::new(&self.0 * &rhs.0)
    }

    fn pow(&self, exponent: &BigUint) -> Self {
        Self(self.0.modpow(exponent, &modulus()))
    }

    fn inverse(&self) -> Self {
        self.pow(&(modulus() - BigUint::from(2u32)))
    }

    fn inv_sqrt(&self) -> Self {
        // p = 5 (mod 8): sqrt(x) = x^((p+3)/8), with sqrt(-1) correction.
        let p = modulus();
        let mut root = self.pow(&((&p + BigUint::from(3u32)) >> 3));
        if root.mul(&root) != *self {
            let sqrt_m1 = Fp(BigUint::from(2u32).modpow(&((&p - BigUint::one()) >> 2), &p));
            root = root.mul(&sqrt_m1);
        }
        assert_eq!(root.mul(&root), *self, "Ristretto witness is not square");
        root.inverse()
    }

    fn is_negative(&self) -> bool {
        (&self.0 & BigUint::one()) == BigUint::one()
    }

    fn limbs(&self) -> [u32; LIMBS] {
        let bytes = self.0.to_bytes_le();
        let mut out = [0u32; LIMBS];
        for (i, byte) in bytes.into_iter().enumerate().take(LIMBS) {
            out[i] = u32::from(byte);
        }
        out
    }
}

#[derive(Clone, Copy)]
struct Value {
    idx: usize,
    cols: [usize; LIMBS],
}

#[derive(Clone)]
enum Op {
    Equal {
        a: Value,
        b: Value,
    },
    Add {
        a: Value,
        b: Value,
        out: Value,
        carries: [usize; LIMBS],
        k: usize,
        subtract: bool,
    },
    Mul {
        a: Value,
        b: Value,
        out: Value,
        k: [usize; LIMBS],
        carries: [usize; 63],
    },
}

#[derive(Clone)]
struct CurveAir {
    log_size: u32,
    num_columns: usize,
    ops: Vec<Op>,
}

impl FrameworkEval for CurveAir {
    fn log_size(&self) -> u32 {
        self.log_size
    }

    fn max_constraint_log_degree_bound(&self) -> u32 {
        self.log_size + 1
    }

    fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
        let columns: Vec<E::F> = (0..self.num_columns)
            .map(|_| eval.next_trace_mask())
            .collect();
        let base = E::F::from(M31::from(RADIX as u32));
        let modulus_limbs = modulus_limbs();
        for op in &self.ops {
            match op {
                Op::Equal { a, b } => {
                    for limb in 0..LIMBS {
                        eval.add_constraint(
                            columns[a.cols[limb]].clone() - columns[b.cols[limb]].clone(),
                        );
                    }
                }
                Op::Add {
                    a,
                    b,
                    out,
                    carries,
                    k,
                    subtract,
                } => {
                    let mut carry = E::F::from(M31::from(0u32));
                    let k_value = columns[*k].clone();
                    for limb in 0..LIMBS {
                        let mut constraint = columns[a.cols[limb]].clone();
                        if *subtract {
                            constraint = constraint - columns[b.cols[limb]].clone();
                        } else {
                            constraint += columns[b.cols[limb]].clone();
                        }
                        constraint = constraint - columns[out.cols[limb]].clone();
                        constraint += carry.clone();
                        constraint = constraint
                            - k_value.clone() * E::F::from(M31::from(modulus_limbs[limb]));
                        constraint = constraint - columns[carries[limb]].clone() * base.clone();
                        eval.add_constraint(constraint);
                        carry = columns[carries[limb]].clone();
                    }
                    eval.add_constraint(carry);
                }
                Op::Mul {
                    a,
                    b,
                    out,
                    k,
                    carries,
                } => {
                    let mut carry = E::F::from(M31::from(0u32));
                    for limb in 0..64 {
                        let mut constraint = carry.clone();
                        for i in 0..LIMBS {
                            if limb >= i && limb - i < LIMBS {
                                constraint +=
                                    columns[a.cols[i]].clone() * columns[b.cols[limb - i]].clone();
                            }
                        }
                        if limb < LIMBS {
                            constraint = constraint - columns[out.cols[limb]].clone();
                        }
                        for k_limb in 0..LIMBS {
                            if limb >= k_limb && limb - k_limb < LIMBS {
                                constraint = constraint
                                    - columns[k[k_limb]].clone()
                                        * E::F::from(M31::from(modulus_limbs[limb - k_limb]));
                            }
                        }
                        if limb < 63 {
                            constraint = constraint - columns[carries[limb]].clone() * base.clone();
                            carry = columns[carries[limb]].clone();
                        }
                        eval.add_constraint(constraint);
                    }
                }
            }
        }
        eval
    }
}

struct Builder {
    columns: Vec<Vec<M31>>,
    values: Vec<Fp>,
    ops: Vec<Op>,
}

impl Builder {
    fn new() -> Self {
        Self {
            columns: Vec::new(),
            values: Vec::new(),
            ops: Vec::new(),
        }
    }

    fn value(&mut self, value: Fp) -> Value {
        let limbs = value.limbs();
        let mut cols = [0usize; LIMBS];
        for (i, limb) in limbs.into_iter().enumerate() {
            cols[i] = self.columns.len();
            self.columns.push(vec![M31::from(limb); 1 << LOG_SIZE]);
        }
        let idx = self.values.len();
        self.values.push(value);
        Value { idx, cols }
    }

    fn add(&mut self, a: Value, b: Value, subtract: bool) -> Value {
        let av = self.values[a.idx].clone();
        let bv = self.values[b.idx].clone();
        let value = if subtract { av.sub(&bv) } else { av.add(&bv) };
        let out = self.value(value);
        let mut carries = [0usize; LIMBS];
        let mut carry = 0i64;
        let al = av.limbs();
        let bl = bv.limbs();
        let cl = self.values[out.idx].limbs();
        for i in 0..LIMBS {
            let lhs = if subtract {
                i64::from(al[i]) - i64::from(bl[i])
            } else {
                i64::from(al[i]) + i64::from(bl[i])
            };
            let k = if subtract {
                if av.0 >= bv.0 { 0i64 } else { -1i64 }
            } else if (&av.0 + &bv.0) >= modulus() {
                1
            } else {
                0
            };
            let term = lhs - i64::from(cl[i]) - k * i64::from(modulus_limbs()[i]) + carry;
            carry = term.div_euclid(RADIX as i64);
            carries[i] = self.columns.len();
            self.columns.push(vec![signed_m31(carry); 1 << LOG_SIZE]);
        }
        let k = if subtract {
            if av.0 >= bv.0 { 0 } else { -1 }
        } else if (&av.0 + &bv.0) >= modulus() {
            1
        } else {
            0
        };
        let k_col = self.columns.len();
        self.columns.push(vec![signed_m31(k); 1 << LOG_SIZE]);
        self.ops.push(Op::Add {
            a,
            b,
            out,
            carries,
            k: k_col,
            subtract,
        });
        out
    }

    fn sub(&mut self, a: Value, b: Value) -> Value {
        self.add(a, b, true)
    }

    fn assert_equal(&mut self, a: Value, b: Value) {
        self.ops.push(Op::Equal { a, b });
    }

    fn mul(&mut self, a: Value, b: Value) -> Value {
        let av = self.values[a.idx].clone();
        let bv = self.values[b.idx].clone();
        let product = &av.0 * &bv.0;
        let p = modulus();
        let (k_big, c_big) = (&product / &p, &product % &p);
        let out = self.value(Fp(c_big));
        let kl = {
            let bytes = k_big.to_bytes_le();
            let mut limbs = [0u32; LIMBS];
            for (i, byte) in bytes.into_iter().enumerate().take(LIMBS) {
                limbs[i] = u32::from(byte);
            }
            limbs
        };
        let al = av.limbs();
        let bl = bv.limbs();
        let cl = self.values[out.idx].limbs();
        let mut k_cols = [0usize; LIMBS];
        for (i, limb) in kl.into_iter().enumerate() {
            k_cols[i] = self.columns.len();
            self.columns.push(vec![M31::from(limb); 1 << LOG_SIZE]);
        }
        let mut carries = [0usize; 63];
        let mut carry = 0i64;
        for limb in 0..64 {
            let mut convolution = 0i64;
            for i in 0..LIMBS {
                if limb >= i && limb - i < LIMBS {
                    convolution += i64::from(al[i]) * i64::from(bl[limb - i]);
                }
            }
            let c = if limb < LIMBS { i64::from(cl[limb]) } else { 0 };
            let mut k_term = 0i64;
            for k_limb in 0..LIMBS {
                if limb >= k_limb && limb - k_limb < LIMBS {
                    k_term -= i64::from(kl[k_limb]) * i64::from(modulus_limbs()[limb - k_limb]);
                }
            }
            let term = convolution - c + k_term + carry;
            carry = term.div_euclid(RADIX as i64);
            if limb < 63 {
                carries[limb] = self.columns.len();
                self.columns.push(vec![signed_m31(carry); 1 << LOG_SIZE]);
            } else {
                assert_eq!(
                    carry, 0,
                    "non-native product carry did not clear: limb={limb}, convolution={convolution}, c={c}, k_term={k_term}, term={term}, k={k_big}",
                );
            }
        }
        self.ops.push(Op::Mul {
            a,
            b,
            out,
            k: k_cols,
            carries,
        });
        out
    }

    fn inv_sqrt(&mut self, a: Value, av: &Fp) -> Value {
        let inv = av.inv_sqrt();
        let inv_value = self.value(inv);
        let square = self.mul(inv_value, inv_value);
        let product = self.mul(a, square);
        let one = self.value(Fp::one());
        self.assert_equal(product, one);
        inv_value
    }
}

#[derive(Clone, Copy)]
struct Point {
    x: Value,
    y: Value,
    z: Value,
    t: Value,
}

fn edwards_add(b: &mut Builder, p: Point, q: Point, d2: Value) -> Point {
    let ymx = b.sub(p.y, p.x);
    let ymx2 = b.sub(q.y, q.x);
    let a = b.mul(ymx, ymx2);
    let ypx = b.add(p.y, p.x, false);
    let ypx2 = b.add(q.y, q.x, false);
    let bb = b.mul(ypx, ypx2);
    let tt = b.mul(p.t, q.t);
    let c = b.mul(tt, d2);
    let zz = b.mul(p.z, q.z);
    let dd = b.add(zz, zz, false);
    let e = b.sub(bb, a);
    let f = b.sub(dd, c);
    let g = b.add(dd, c, false);
    let h = b.add(bb, a, false);
    Point {
        x: b.mul(e, f),
        y: b.mul(g, h),
        t: b.mul(e, h),
        z: b.mul(f, g),
    }
}

fn ristretto_compress(b: &mut Builder, p: Point, sqrt_m1: Value, magic: Value) -> Value {
    let z_plus_y = b.add(p.z, p.y, false);
    let z_minus_y = b.sub(p.z, p.y);
    let u1 = b.mul(z_plus_y, z_minus_y);
    let u2 = b.mul(p.x, p.y);
    let u2sq = b.mul(u2, u2);
    let v = b.mul(u1, u2sq);
    let v_value = b.values[v.idx].clone();
    let inv = b.inv_sqrt(v, &v_value);
    let i1 = b.mul(inv, u1);
    let i2 = b.mul(inv, u2);
    let i2t = b.mul(i2, p.t);
    let zinv = b.mul(i1, i2t);
    let ix = b.mul(p.x, sqrt_m1);
    let iy = b.mul(p.y, sqrt_m1);
    let enchanted = b.mul(i1, magic);
    let tz_is_negative = b.values[p.t.idx].mul(&b.values[zinv.idx]).is_negative();
    let den = if tz_is_negative { enchanted } else { i2 };
    let _x = if b.values[p.x.idx].mul(&b.values[zinv.idx]).is_negative() {
        iy
    } else {
        p.x
    };
    let y = if tz_is_negative { ix } else { p.y };
    let z_minus_y = b.sub(p.z, y);
    let s = b.mul(den, z_minus_y);
    if b.values[s.idx].is_negative() {
        let zero = b.value(Fp::zero());
        b.sub(zero, s)
    } else {
        s
    }
}

fn build(name: &str) -> (CurveAir, Vec<Vec<M31>>, usize, usize) {
    let mut b = Builder::new();
    let x = Fp::from_decimal(
        "15112221349535400772501151409588531511454012693041857206046113283949847762202",
    );
    let y = Fp::from_decimal(
        "46316835694926478169428394003475163141307993866256225615783033603165251855960",
    );
    let one = b.value(Fp::one());
    let zero = b.value(Fp::zero());
    let base = Point {
        x: b.value(x.clone()),
        y: b.value(y.clone()),
        z: one,
        t: b.value(x.mul(&y)),
    };
    let d = Fp::from_decimal(
        "37095705934669439343138083508754565189542113879843219016388785533085940283555",
    );
    let d2 = b.value(d.add(&d));
    let sqrt_m1 = Fp::from_radix_51([
        1718705420411056,
        234908883556509,
        2233514472574048,
        2117202627021982,
        765476049583133,
    ]);
    let magic = Fp::from_radix_51([
        278908739862762,
        821645201101625,
        8113234426968,
        1777959178193151,
        2118520810568447,
    ]);
    let q = edwards_add(&mut b, base, base, d2);
    if name == "edwards25519" {
        let _ = q;
    } else {
        let sm1 = b.value(sqrt_m1.clone());
        let mg = b.value(magic.clone());
        let s = ristretto_compress(&mut b, q, sm1, mg);
        let ss = b.mul(s, s);
        let u1 = b.sub(one, ss);
        let u2 = b.add(one, ss, false);
        let u2sq = b.mul(u2, u2);
        let u1sq = b.mul(u1, u1);
        let d_value = b.value(d.neg());
        let d_u1sq = b.mul(d_value, u1sq);
        let v = b.sub(d_u1sq, u2sq);
        let v_value = b.values[v.idx].clone();
        let inv = b.inv_sqrt(v, &v_value);
        let dx = b.mul(inv, u2);
        let dxv = b.mul(dx, v);
        let dy = b.mul(inv, dxv);
        let s2 = b.add(s, s, false);
        let x2 = b.mul(s2, dx);
        let y2 = b.mul(u1, dy);
        let _t2 = b.mul(x2, y2);
    }
    let _ = zero;
    let air = CurveAir {
        log_size: LOG_SIZE,
        num_columns: b.columns.len(),
        ops: b.ops.clone(),
    };
    let constraints = b
        .ops
        .iter()
        .map(|op| match op {
            Op::Equal { .. } => LIMBS,
            Op::Add { .. } => LIMBS + 1,
            Op::Mul { .. } => 64,
        })
        .sum();
    (air, b.columns, b.ops.len(), constraints)
}

fn evaluations(columns: &[Vec<M31>]) -> Vec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>> {
    let domain = CanonicCoset::new(LOG_SIZE).circle_domain();
    columns
        .iter()
        .map(|col| {
            CircleEvaluation::<SimdBackend, M31, NaturalOrder>::new(
                domain,
                BaseColumn::from_cpu(col),
            )
            .bit_reverse()
        })
        .collect()
}

fn measure(name: &str) {
    let (air, columns, ops, arithmetic_constraints) = build(name);
    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(&mut allocator, air.clone(), SecureField::from(0u32));
    println!(
        "{name}: columns={} ops={} constraints={} arithmetic_constraints={arithmetic_constraints}",
        columns.len(),
        ops,
        component.n_constraints()
    );
    let config = PcsConfig {
        pow_bits: 2,
        fri_config: FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };
    let twiddles = SimdBackend::precompute_twiddles(CanonicCoset::new(LOG_SIZE + 1).half_coset());
    let mut channel = Poseidon252Channel::default();
    let mut scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::new(config, &twiddles);
    {
        let mut tree = scheme.tree_builder();
        tree.extend_evals(vec![]);
        tree.commit(&mut channel);
    }
    {
        let mut tree = scheme.tree_builder();
        tree.extend_evals(evaluations(&columns));
        tree.commit(&mut channel);
    }
    let start = Instant::now();
    let proof =
        prove(&[&component], &mut channel, scheme).expect("AIR witness satisfies constraints");
    let prove_ms = start.elapsed().as_secs_f64() * 1000.0;
    let mut verify_channel = Poseidon252Channel::default();
    let mut verifier = CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
    verifier.commit(proof.commitments[0], &[], &mut verify_channel);
    verifier.commit(
        proof.commitments[1],
        &vec![LOG_SIZE; columns.len()],
        &mut verify_channel,
    );
    let mut allocator = TraceLocationAllocator::default();
    let verify_component = FrameworkComponent::new(&mut allocator, air, SecureField::from(0u32));
    let start = Instant::now();
    verify(
        &[&verify_component],
        &mut verify_channel,
        &mut verifier,
        proof,
    )
    .expect("proof verifies");
    let verify_ms = start.elapsed().as_secs_f64() * 1000.0;
    println!("  prove={prove_ms:.2} ms verify={verify_ms:.2} ms");
}

fn main() {
    measure("edwards25519");
    measure("ristretto255");
}
