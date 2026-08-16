use poker_protocol_core::{
    CryptoTranscript, Curve, CurvePoint, CurveScalar, ElGamalCiphertextGeneric, VerificationError,
};
use rand_core::{CryptoRng, RngCore};

const PROTOCOL_ID: &[u8] = b"poker/bayer-groth-shuffle/v2";
const COMMITMENT_H_DOMAIN: &[u8] = b"poker/bg12/v2/H";

#[derive(Debug, Clone)]
struct CommitmentKey<C: Curve> {
    h: C::Point,
    generators: Vec<C::Point>,
}

impl<C: Curve> CommitmentKey<C> {
    fn derive(n: usize) -> Result<Self, VerificationError> {
        let h = C::hash_to_curve(COMMITMENT_H_DOMAIN);
        let generators: Vec<C::Point> = (0..n)
            .map(|i| C::hash_to_curve(format!("poker/bg12/v2/G/{n}/{i}").as_bytes()))
            .collect();

        if h.is_identity() || h == C::base_g() {
            return Err(VerificationError::InvalidCommitmentKey);
        }
        for (i, generator) in generators.iter().enumerate() {
            if generator.is_identity() || *generator == C::base_g() || *generator == h {
                return Err(VerificationError::InvalidCommitmentKey);
            }
            if generators[..i].contains(generator) {
                return Err(VerificationError::InvalidCommitmentKey);
            }
        }
        Ok(Self { h, generators })
    }

    fn scalar_commit(&self, value: C::Scalar, blinding: C::Scalar) -> C::Point {
        C::base_g() * value + self.h * blinding
    }

    fn vector_commit(
        &self,
        values: &[C::Scalar],
        blinding: C::Scalar,
    ) -> Result<C::Point, VerificationError> {
        if values.len() != self.generators.len() {
            return Err(VerificationError::LengthMismatch);
        }
        let mut scalars = Vec::with_capacity(values.len() + 1);
        scalars.extend_from_slice(values);
        scalars.push(blinding);
        let mut points = self.generators.clone();
        points.push(self.h);
        Ok(C::Point::vartime_multiscalar_mul(&scalars, &points))
    }
}

/// The Bayer--Groth multi-exponentiation argument.
#[derive(Debug, Clone)]
pub struct MultiExponentiationArgument<C: Curve> {
    pub c_alpha: C::Point,
    pub c_beta: C::Point,
    pub ciphertext_0: ElGamalCiphertextGeneric<C>,
    pub ciphertext_1: ElGamalCiphertextGeneric<C>,
    /// `alpha + challenge * x^pi`; fresh `alpha` information-theoretically
    /// masks the hidden permutation-dependent vector.
    pub alpha_response: Vec<C::Scalar>,
    pub commitment_response: C::Scalar,
    pub beta: C::Scalar,
    pub beta_blinding_response: C::Scalar,
    pub rerandomization_response: C::Scalar,
}

/// The Bayer--Groth single-value product argument used for `m = 1`.
#[derive(Debug, Clone)]
pub struct ProductArgument<C: Curve> {
    pub c_d: C::Point,
    pub c_delta: C::Point,
    pub c_capital_delta: C::Point,
    /// Masked Sigma responses, not raw permutation coefficients.
    pub a_response: Vec<C::Scalar>,
    pub b_response: Vec<C::Scalar>,
    pub r_response: C::Scalar,
    pub s_response: C::Scalar,
}

/// Bayer--Groth shuffle proof, protocol version 2.
#[derive(Debug, Clone)]
pub struct BayerGrothShuffleProof<C: Curve> {
    pub c_permutation: C::Point,
    pub c_permuted_powers: C::Point,
    pub multi_exponentiation: MultiExponentiationArgument<C>,
    pub product: ProductArgument<C>,
}

fn scalar_pow<S: CurveScalar>(mut base: S, mut exponent: usize) -> S {
    let mut result = S::one();
    while exponent != 0 {
        if exponent & 1 == 1 {
            result = result * base;
        }
        base = base * base;
        exponent >>= 1;
    }
    result
}

fn challenge_nonzero<C: Curve>(transcript: &mut impl CryptoTranscript, label: &[u8]) -> C::Scalar {
    let mut challenge = transcript.challenge::<C>(label).scalar;
    let mut counter = 0u32;
    while challenge == C::Scalar::zero() {
        transcript.append_message(b"bg12_zero_challenge_retry", &counter.to_le_bytes());
        challenge = transcript.challenge::<C>(label).scalar;
        counter = counter.wrapping_add(1);
    }
    challenge
}

fn append_ciphertext<C: Curve>(
    transcript: &mut impl CryptoTranscript,
    label: &[u8],
    ciphertext: &ElGamalCiphertextGeneric<C>,
) {
    transcript.append_message(b"bg12_ciphertext_label", label);
    transcript.append_point::<C>(b"bg12_ciphertext_c1", &ciphertext.c1);
    transcript.append_point::<C>(b"bg12_ciphertext_c2", &ciphertext.c2);
}

fn append_statement<C: Curve>(
    transcript: &mut impl CryptoTranscript,
    input: &[ElGamalCiphertextGeneric<C>],
    output: &[ElGamalCiphertextGeneric<C>],
    public_key: &C::Point,
    c_permutation: &C::Point,
) {
    transcript.append_message(b"bg12_protocol", PROTOCOL_ID);
    transcript.append_message(b"bg12_deck_size", &(input.len() as u64).to_le_bytes());
    transcript.append_point::<C>(b"bg12_public_key", public_key);
    for ciphertext in input {
        append_ciphertext::<C>(transcript, b"input", ciphertext);
    }
    for ciphertext in output {
        append_ciphertext::<C>(transcript, b"output", ciphertext);
    }
    transcript.append_point::<C>(b"bg12_c_permutation", c_permutation);
}

fn ciphertext_msm<C: Curve>(
    ciphertexts: &[ElGamalCiphertextGeneric<C>],
    scalars: &[C::Scalar],
) -> Result<ElGamalCiphertextGeneric<C>, VerificationError> {
    if ciphertexts.is_empty() || ciphertexts.len() != scalars.len() {
        return Err(VerificationError::LengthMismatch);
    }
    let c1_points: Vec<C::Point> = ciphertexts.iter().map(|ciphertext| ciphertext.c1).collect();
    let c2_points: Vec<C::Point> = ciphertexts.iter().map(|ciphertext| ciphertext.c2).collect();
    Ok(ElGamalCiphertextGeneric {
        c1: C::Point::vartime_multiscalar_mul(scalars, &c1_points),
        c2: C::Point::vartime_multiscalar_mul(scalars, &c2_points),
    })
}

fn validate_statement<C: Curve>(
    input: &[ElGamalCiphertextGeneric<C>],
    output: &[ElGamalCiphertextGeneric<C>],
    public_key: &C::Point,
) -> Result<(), VerificationError> {
    if input.len() < 2 || input.len() != output.len() {
        return Err(VerificationError::InvalidInput);
    }
    if public_key.is_identity()
        || input
            .iter()
            .chain(output)
            .any(|ciphertext| ciphertext.c1.is_identity() || ciphertext.c2.is_identity())
    {
        return Err(VerificationError::IdentityBasePoint);
    }
    Ok(())
}

fn validate_proof_shape<C: Curve>(
    proof: &BayerGrothShuffleProof<C>,
    n: usize,
) -> Result<(), VerificationError> {
    if proof.multi_exponentiation.alpha_response.len() != n
        || proof.product.a_response.len() != n
        || proof.product.b_response.len() != n
    {
        return Err(VerificationError::LengthMismatch);
    }
    let points = [
        proof.c_permutation,
        proof.c_permuted_powers,
        proof.multi_exponentiation.c_alpha,
        proof.multi_exponentiation.c_beta,
        proof.multi_exponentiation.ciphertext_0.c1,
        proof.multi_exponentiation.ciphertext_0.c2,
        proof.multi_exponentiation.ciphertext_1.c1,
        proof.multi_exponentiation.ciphertext_1.c2,
        proof.product.c_d,
        proof.product.c_delta,
        proof.product.c_capital_delta,
    ];
    if points.iter().any(CurvePoint::is_identity) {
        return Err(VerificationError::IdentityBasePoint);
    }
    Ok(())
}

impl<C: Curve> BayerGrothShuffleProof<C> {
    pub fn prove(
        input: &[ElGamalCiphertextGeneric<C>],
        output: &[ElGamalCiphertextGeneric<C>],
        permutation: &[usize],
        rerandomizers: &[C::Scalar],
        public_key: &C::Point,
        rng: &mut (impl CryptoRng + RngCore),
        transcript: &mut impl CryptoTranscript,
    ) -> Result<Self, VerificationError> {
        validate_statement(input, output, public_key)?;
        let n = input.len();
        if rerandomizers.len() != n {
            return Err(VerificationError::InvalidRerandomizerCount);
        }
        if permutation.len() != n {
            return Err(VerificationError::InvalidPermutation);
        }
        let mut seen = vec![false; n];
        for &index in permutation {
            if index >= n || seen[index] {
                return Err(VerificationError::InvalidPermutation);
            }
            seen[index] = true;
        }
        for i in 0..n {
            if output[i] != input[permutation[i]].re_encrypt(public_key, &rerandomizers[i]) {
                return Err(VerificationError::InvalidInput);
            }
        }

        let commitment_key = CommitmentKey::<C>::derive(n)?;
        let pi: Vec<C::Scalar> = permutation
            .iter()
            .map(|index| C::Scalar::from_u64((*index as u64) + 1))
            .collect();
        let permutation_blinding = C::Scalar::random(rng);
        let c_permutation = commitment_key.vector_commit(&pi, permutation_blinding)?;

        append_statement::<C>(transcript, input, output, public_key, &c_permutation);
        let powers_challenge = challenge_nonzero::<C>(transcript, b"bg12_powers_challenge");
        let permuted_powers: Vec<C::Scalar> = permutation
            .iter()
            .map(|index| scalar_pow(powers_challenge, index + 1))
            .collect();
        let powers_blinding = C::Scalar::random(rng);
        let c_permuted_powers = commitment_key.vector_commit(&permuted_powers, powers_blinding)?;
        transcript.append_point::<C>(b"bg12_c_permuted_powers", &c_permuted_powers);
        let product_y = challenge_nonzero::<C>(transcript, b"bg12_product_y");
        let product_z = challenge_nonzero::<C>(transcript, b"bg12_product_z");

        let alpha: Vec<C::Scalar> = (0..n).map(|_| C::Scalar::random(rng)).collect();
        let beta = C::Scalar::random(rng);
        let alpha_blinding = C::Scalar::random(rng);
        let beta_blinding = C::Scalar::random(rng);
        let c_alpha = commitment_key.vector_commit(&alpha, alpha_blinding)?;
        let c_beta = commitment_key.scalar_commit(beta, beta_blinding);
        let tau_0 = C::Scalar::random(rng);
        let output_alpha = ciphertext_msm::<C>(output, &alpha)?;
        let ciphertext_0 = ElGamalCiphertextGeneric {
            c1: C::base_g() * tau_0 + output_alpha.c1,
            c2: C::base_g() * beta + *public_key * tau_0 + output_alpha.c2,
        };
        let rho_aggregate = -(0..n)
            .map(|i| rerandomizers[i] * permuted_powers[i])
            .sum::<C::Scalar>();
        let output_powers = ciphertext_msm::<C>(output, &permuted_powers)?;
        let ciphertext_1 = ElGamalCiphertextGeneric {
            c1: C::base_g() * rho_aggregate + output_powers.c1,
            c2: *public_key * rho_aggregate + output_powers.c2,
        };
        transcript.append_point::<C>(b"bg12_mexp_c_alpha", &c_alpha);
        transcript.append_point::<C>(b"bg12_mexp_c_beta", &c_beta);
        append_ciphertext::<C>(transcript, b"mexp_0", &ciphertext_0);
        append_ciphertext::<C>(transcript, b"mexp_1", &ciphertext_1);
        let mexp_challenge = challenge_nonzero::<C>(transcript, b"bg12_mexp_challenge");
        let alpha_response: Vec<C::Scalar> = (0..n)
            .map(|i| alpha[i] + mexp_challenge * permuted_powers[i])
            .collect();
        let multi_exponentiation = MultiExponentiationArgument {
            c_alpha,
            c_beta,
            ciphertext_0,
            ciphertext_1,
            alpha_response,
            commitment_response: alpha_blinding + mexp_challenge * powers_blinding,
            beta,
            beta_blinding_response: beta_blinding,
            rerandomization_response: tau_0 + mexp_challenge * rho_aggregate,
        };

        let d: Vec<C::Scalar> = (0..n).map(|_| C::Scalar::random(rng)).collect();
        let d_blinding = C::Scalar::random(rng);
        let c_d = commitment_key.vector_commit(&d, d_blinding)?;
        let mut delta = vec![C::Scalar::zero(); n];
        delta[0] = d[0];
        for value in delta.iter_mut().take(n - 1).skip(1) {
            *value = C::Scalar::random(rng);
        }
        let mut delta_products = vec![C::Scalar::zero(); n];
        for i in 0..n - 1 {
            delta_products[i] = -(delta[i] * d[i + 1]);
        }
        let delta_blinding = C::Scalar::random(rng);
        let c_delta = commitment_key.vector_commit(&delta_products, delta_blinding)?;
        let a: Vec<C::Scalar> = (0..n)
            .map(|i| product_y * pi[i] + permuted_powers[i] - product_z)
            .collect();
        let mut b = vec![C::Scalar::one(); n];
        b[0] = a[0];
        for i in 1..n {
            b[i] = b[i - 1] * a[i];
        }
        let mut capital_delta = vec![C::Scalar::zero(); n];
        for i in 0..n - 1 {
            capital_delta[i] = delta[i + 1] - a[i + 1] * delta[i] - b[i] * d[i + 1];
        }
        let capital_delta_blinding = C::Scalar::random(rng);
        let c_capital_delta =
            commitment_key.vector_commit(&capital_delta, capital_delta_blinding)?;
        transcript.append_point::<C>(b"bg12_product_c_d", &c_d);
        transcript.append_point::<C>(b"bg12_product_c_delta", &c_delta);
        transcript.append_point::<C>(b"bg12_product_c_capital_delta", &c_capital_delta);
        let product_challenge = challenge_nonzero::<C>(transcript, b"bg12_product_challenge");
        let a_response: Vec<C::Scalar> = (0..n).map(|i| product_challenge * a[i] + d[i]).collect();
        let b_response: Vec<C::Scalar> = (0..n)
            .map(|i| product_challenge * b[i] + delta[i])
            .collect();
        let a_blinding = product_y * permutation_blinding + powers_blinding;
        let product = ProductArgument {
            c_d,
            c_delta,
            c_capital_delta,
            a_response,
            b_response,
            r_response: product_challenge * a_blinding + d_blinding,
            s_response: product_challenge * capital_delta_blinding + delta_blinding,
        };

        Ok(Self {
            c_permutation,
            c_permuted_powers,
            multi_exponentiation,
            product,
        })
    }

    pub fn verify(
        &self,
        input: &[ElGamalCiphertextGeneric<C>],
        output: &[ElGamalCiphertextGeneric<C>],
        public_key: &C::Point,
        transcript: &mut impl CryptoTranscript,
    ) -> Result<(), VerificationError> {
        validate_statement(input, output, public_key)?;
        let n = input.len();
        validate_proof_shape(self, n)?;
        let commitment_key = CommitmentKey::<C>::derive(n)?;

        append_statement::<C>(transcript, input, output, public_key, &self.c_permutation);
        let powers_challenge = challenge_nonzero::<C>(transcript, b"bg12_powers_challenge");
        transcript.append_point::<C>(b"bg12_c_permuted_powers", &self.c_permuted_powers);
        let product_y = challenge_nonzero::<C>(transcript, b"bg12_product_y");
        let product_z = challenge_nonzero::<C>(transcript, b"bg12_product_z");

        let mexp = &self.multi_exponentiation;
        transcript.append_point::<C>(b"bg12_mexp_c_alpha", &mexp.c_alpha);
        transcript.append_point::<C>(b"bg12_mexp_c_beta", &mexp.c_beta);
        append_ciphertext::<C>(transcript, b"mexp_0", &mexp.ciphertext_0);
        append_ciphertext::<C>(transcript, b"mexp_1", &mexp.ciphertext_1);
        let mexp_challenge = challenge_nonzero::<C>(transcript, b"bg12_mexp_challenge");

        let public_powers: Vec<C::Scalar> =
            (1..=n).map(|i| scalar_pow(powers_challenge, i)).collect();
        let expected_ciphertext_1 = ciphertext_msm::<C>(input, &public_powers)?;
        if mexp.ciphertext_1 != expected_ciphertext_1 {
            return Err(VerificationError::InvalidBayerGrothProof);
        }
        let commitment_lhs = self.c_permuted_powers * mexp_challenge + mexp.c_alpha;
        let commitment_rhs =
            commitment_key.vector_commit(&mexp.alpha_response, mexp.commitment_response)?;
        if commitment_lhs != commitment_rhs
            || mexp.c_beta != commitment_key.scalar_commit(mexp.beta, mexp.beta_blinding_response)
        {
            return Err(VerificationError::InvalidBayerGrothProof);
        }
        let output_response = ciphertext_msm::<C>(output, &mexp.alpha_response)?;
        let ciphertext_lhs: ElGamalCiphertextGeneric<C> = ElGamalCiphertextGeneric {
            c1: mexp.ciphertext_0.c1 + mexp.ciphertext_1.c1 * mexp_challenge,
            c2: mexp.ciphertext_0.c2 + mexp.ciphertext_1.c2 * mexp_challenge,
        };
        let ciphertext_rhs: ElGamalCiphertextGeneric<C> = ElGamalCiphertextGeneric {
            c1: C::base_g() * mexp.rerandomization_response + output_response.c1,
            c2: C::base_g() * mexp.beta
                + *public_key * mexp.rerandomization_response
                + output_response.c2,
        };
        if ciphertext_lhs != ciphertext_rhs {
            return Err(VerificationError::InvalidBayerGrothProof);
        }

        let product = &self.product;
        transcript.append_point::<C>(b"bg12_product_c_d", &product.c_d);
        transcript.append_point::<C>(b"bg12_product_c_delta", &product.c_delta);
        transcript.append_point::<C>(b"bg12_product_c_capital_delta", &product.c_capital_delta);
        let product_challenge = challenge_nonzero::<C>(transcript, b"bg12_product_challenge");
        let minus_z = vec![-product_z; n];
        let c_minus_z = commitment_key.vector_commit(&minus_z, C::Scalar::zero())?;
        let c_a = self.c_permutation * product_y + self.c_permuted_powers;
        let product_check_1_lhs = product.c_d + (c_a + c_minus_z) * product_challenge;
        let product_check_1_rhs =
            commitment_key.vector_commit(&product.a_response, product.r_response)?;
        if product_check_1_lhs != product_check_1_rhs {
            return Err(VerificationError::InvalidBayerGrothProof);
        }
        let mut recurrence = vec![C::Scalar::zero(); n];
        for i in 0..n - 1 {
            recurrence[i] = product_challenge * product.b_response[i + 1]
                - product.b_response[i] * product.a_response[i + 1];
        }
        let product_check_2_lhs = product.c_delta + product.c_capital_delta * product_challenge;
        let product_check_2_rhs = commitment_key.vector_commit(&recurrence, product.s_response)?;
        if product_check_2_lhs != product_check_2_rhs
            || product.b_response[0] != product.a_response[0]
        {
            return Err(VerificationError::InvalidBayerGrothProof);
        }
        let expected_product = (1..=n)
            .map(|i| {
                product_y * C::Scalar::from_u64(i as u64) + scalar_pow(powers_challenge, i)
                    - product_z
            })
            .fold(C::Scalar::one(), |acc, value| acc * value);
        if product.b_response[n - 1] != product_challenge * expected_product {
            return Err(VerificationError::InvalidBayerGrothProof);
        }
        Ok(())
    }
}
