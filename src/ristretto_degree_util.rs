//! Internal expression-degree evaluator for Ristretto primitives.

use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub};

use stwo::core::fields::m31::M31;
use stwo::core::fields::qm31::{SECURE_EXTENSION_DEGREE, SecureField};
use stwo_constraint_framework::EvalAtRow;

#[derive(Clone, Copy, Debug)]
pub(crate) struct DegreeEvaluator {
    pub(crate) max: usize,
}

impl num_traits::One for DegreeEvaluator {
    fn one() -> Self {
        Self { max: 0 }
    }
}

impl num_traits::Zero for DegreeEvaluator {
    fn zero() -> Self {
        Self { max: 0 }
    }

    fn is_zero(&self) -> bool {
        self.max == 0
    }
}

impl stwo::core::fields::FieldExpOps for DegreeEvaluator {
    fn inverse(&self) -> Self {
        *self
    }
}

impl Add for DegreeEvaluator {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        Self {
            max: self.max.max(rhs.max),
        }
    }
}

impl Sub for DegreeEvaluator {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        Self {
            max: self.max.max(rhs.max),
        }
    }
}

impl Mul for DegreeEvaluator {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        Self {
            max: self.max + rhs.max,
        }
    }
}

impl Neg for DegreeEvaluator {
    type Output = Self;
    fn neg(self) -> Self {
        self
    }
}

impl AddAssign for DegreeEvaluator {
    fn add_assign(&mut self, rhs: Self) {
        self.max = self.max.max(rhs.max);
    }
}

impl MulAssign for DegreeEvaluator {
    fn mul_assign(&mut self, rhs: Self) {
        self.max += rhs.max;
    }
}

impl AddAssign<M31> for DegreeEvaluator {
    fn add_assign(&mut self, _: M31) {}
}

impl Mul<M31> for DegreeEvaluator {
    type Output = Self;
    fn mul(self, _: M31) -> Self {
        self
    }
}

impl Add<M31> for DegreeEvaluator {
    type Output = Self;
    fn add(self, _: M31) -> Self {
        self
    }
}

impl Add<SecureField> for DegreeEvaluator {
    type Output = Self;
    fn add(self, _: SecureField) -> Self {
        self
    }
}

impl Mul<SecureField> for DegreeEvaluator {
    type Output = Self;
    fn mul(self, _: SecureField) -> Self {
        self
    }
}

impl Sub<SecureField> for DegreeEvaluator {
    type Output = Self;
    fn sub(self, _: SecureField) -> Self {
        self
    }
}

impl From<M31> for DegreeEvaluator {
    fn from(_: M31) -> Self {
        Self { max: 0 }
    }
}

impl From<SecureField> for DegreeEvaluator {
    fn from(_: SecureField) -> Self {
        Self { max: 0 }
    }
}

impl EvalAtRow for DegreeEvaluator {
    type F = Self;
    type EF = Self;

    fn next_interaction_mask<const N: usize>(
        &mut self,
        _interaction: usize,
        _offsets: [isize; N],
    ) -> [Self::F; N] {
        std::array::from_fn(|_| Self { max: 1 })
    }

    fn add_constraint<G>(&mut self, constraint: G)
    where
        Self::EF: Mul<G, Output = Self::EF> + From<G>,
    {
        let constraint = Self::EF::from(constraint);
        self.max = self.max.max(constraint.max);
    }

    fn combine_ef(_: [Self::F; SECURE_EXTENSION_DEGREE]) -> Self::EF {
        num_traits::Zero::zero()
    }
}
