//! Blake2b `G`-function AIR baseline over M31.
//!
//! This executable proves a complete Blake2b `G(a, b, c, d, x, y)` step:
//! four wrapping 64-bit additions, four XORs, and rotations by 32, 24, 16,
//! and 63 bits.  Bytes are range-checked by bit decomposition; addition
//! carries are range-checked with two bits.  It is an intentionally simple,
//! wide-row correctness baseline for the optimized lookup-based component.
//! Pass `--compression` to prove one complete fixed-shape Blake2b-256 leaf
//! compression. That mode binds the message, initialized state and output
//! digest directly in the AIR, but remains a deliberately inefficient
//! baseline rather than an admission circuit or sparse-Merkle path proof.

use std::time::Instant;

use stwo::core::air::Component;
use stwo::core::channel::Poseidon252Channel;
use stwo::core::fields::m31::M31;
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

use poker_texas_air::blake2b_smt_witness::{BLAKE2B_IV, Blake2bSmtSingleBlock};

const LOG_SIZE: u32 = 4;
const TRACE_ROWS: usize = 1 << LOG_SIZE;
const WORD_BYTES: usize = 8;
const BYTE_BITS: usize = 8;
// Independently computed from the BLAKE2b G specification for the six input
// words in `build`.  Keep this assertion in the executable so benchmark
// refactors cannot silently benchmark a malformed round relation.
const BLAKE2B_G_KNOWN_OUTPUT: [u64; 4] = [
    0x2133_0908_09c4_3c88,
    0xd625_5124_4d4a_7047,
    0xe4bf_119c_9eb2_e576,
    0x2edf_5843_cced_daf4,
];

#[derive(Clone, Copy)]
struct Word {
    value: u64,
    bytes: [usize; WORD_BYTES],
    bits: [[usize; BYTE_BITS]; WORD_BYTES],
}

#[derive(Clone, Copy)]
struct Carry {
    column: usize,
    bits: [usize; 2],
}

#[derive(Clone)]
enum Op {
    Add {
        a: Word,
        b: Word,
        extra: Option<Word>,
        out: Word,
        carries: [Carry; WORD_BYTES],
    },
    XorRotate {
        a: Word,
        b: Word,
        out: Word,
        right_shift: usize,
    },
}

#[derive(Clone)]
struct Blake2bGAir {
    log_size: u32,
    num_columns: usize,
    words: Vec<Word>,
    ops: Vec<Op>,
    /// Words fixed by the public compression statement. The G benchmark
    /// leaves this empty; compression mode pins block, initialized state and
    /// digest bytes in the AIR.
    public_words: Vec<(Word, u64)>,
}

impl FrameworkEval for Blake2bGAir {
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
        let zero: E::F = M31::from(0u32).into();
        let one: E::F = M31::from(1u32).into();
        let two: E::F = M31::from(2u32).into();
        let byte_base: E::F = M31::from(256u32).into();

        for word in &self.words {
            for byte_index in 0..WORD_BYTES {
                let mut reconstructed: E::F = M31::from(0u32).into();
                for bit_index in 0..BYTE_BITS {
                    let bit = columns[word.bits[byte_index][bit_index]].clone();
                    let weight: E::F = M31::from(1u32 << bit_index).into();
                    eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
                    reconstructed += bit * weight;
                }
                eval.add_constraint(columns[word.bytes[byte_index]].clone() - reconstructed);
            }
        }

        for (word, expected) in &self.public_words {
            for (byte_index, expected_byte) in expected.to_le_bytes().into_iter().enumerate() {
                eval.add_constraint(
                    columns[word.bytes[byte_index]].clone()
                        - E::F::from(M31::from(u32::from(expected_byte))),
                );
            }
        }

        for op in &self.ops {
            match op {
                Op::Add {
                    a,
                    b,
                    extra,
                    out,
                    carries,
                } => {
                    let mut carry_in = zero.clone();
                    for byte_index in 0..WORD_BYTES {
                        let carry = carries[byte_index];
                        let mut carry_reconstructed: E::F = M31::from(0u32).into();
                        for bit_index in 0..2 {
                            let bit = columns[carry.bits[bit_index]].clone();
                            let weight: E::F = M31::from(1u32 << bit_index).into();
                            eval.add_constraint(bit.clone() * (bit.clone() - one.clone()));
                            carry_reconstructed += bit * weight;
                        }
                        eval.add_constraint(columns[carry.column].clone() - carry_reconstructed);

                        let mut sum = columns[a.bytes[byte_index]].clone()
                            + columns[b.bytes[byte_index]].clone()
                            + carry_in;
                        if let Some(extra) = extra {
                            sum += columns[extra.bytes[byte_index]].clone();
                        }
                        eval.add_constraint(
                            sum - columns[out.bytes[byte_index]].clone()
                                - byte_base.clone() * columns[carry.column].clone(),
                        );
                        carry_in = columns[carry.column].clone();
                    }
                }
                Op::XorRotate {
                    a,
                    b,
                    out,
                    right_shift,
                } => {
                    for output_bit in 0..64 {
                        let source_bit = (output_bit + right_shift) % 64;
                        let output = columns[out.bits[output_bit / 8][output_bit % 8]].clone();
                        let left = columns[a.bits[source_bit / 8][source_bit % 8]].clone();
                        let right = columns[b.bits[source_bit / 8][source_bit % 8]].clone();
                        // `out = left XOR right` over Boolean inputs.
                        eval.add_constraint(
                            output - left.clone() - right.clone() + two.clone() * left * right,
                        );
                    }
                }
            }
        }
        eval
    }
}

struct Builder {
    columns: Vec<Vec<M31>>,
    words: Vec<Word>,
    ops: Vec<Op>,
}

impl Builder {
    fn new() -> Self {
        Self {
            columns: Vec::new(),
            words: Vec::new(),
            ops: Vec::new(),
        }
    }

    fn column(&mut self, value: u32) -> usize {
        let index = self.columns.len();
        self.columns.push(vec![M31::from(value); TRACE_ROWS]);
        index
    }

    fn word(&mut self, value: u64) -> Word {
        let mut bytes = [0usize; WORD_BYTES];
        let mut bits = [[0usize; BYTE_BITS]; WORD_BYTES];
        for (byte_index, byte) in value.to_le_bytes().into_iter().enumerate() {
            bytes[byte_index] = self.column(u32::from(byte));
            for bit_index in 0..BYTE_BITS {
                bits[byte_index][bit_index] = self.column(u32::from((byte >> bit_index) & 1));
            }
        }
        let word = Word { value, bytes, bits };
        self.words.push(word);
        word
    }

    fn carry(&mut self, value: u8) -> Carry {
        assert!(value <= 2, "Blake2b byte carry must be at most two");
        Carry {
            column: self.column(u32::from(value)),
            bits: [
                self.column(u32::from(value & 1)),
                self.column(u32::from((value >> 1) & 1)),
            ],
        }
    }

    fn add(&mut self, a: Word, b: Word, extra: Option<Word>) -> Word {
        let extra_value = extra.map_or(0, |word| word.value);
        let out = self.word(a.value.wrapping_add(b.value).wrapping_add(extra_value));
        let a_bytes = a.value.to_le_bytes();
        let b_bytes = b.value.to_le_bytes();
        let extra_bytes = extra_value.to_le_bytes();
        let mut carries = [Carry {
            column: 0,
            bits: [0, 0],
        }; WORD_BYTES];
        let mut carry = 0u16;
        for byte_index in 0..WORD_BYTES {
            let sum = u16::from(a_bytes[byte_index])
                + u16::from(b_bytes[byte_index])
                + u16::from(extra_bytes[byte_index])
                + carry;
            carry = sum >> 8;
            carries[byte_index] = self.carry(carry as u8);
        }
        self.ops.push(Op::Add {
            a,
            b,
            extra,
            out,
            carries,
        });
        out
    }

    fn xor_rotate(&mut self, a: Word, b: Word, right_shift: usize) -> Word {
        let out = self.word((a.value ^ b.value).rotate_right(right_shift as u32));
        self.ops.push(Op::XorRotate {
            a,
            b,
            out,
            right_shift,
        });
        out
    }

    fn g(&mut self, a: Word, b: Word, c: Word, d: Word, x: Word, y: Word) -> [Word; 4] {
        let a1 = self.add(a, b, Some(x));
        let d1 = self.xor_rotate(d, a1, 32);
        let c1 = self.add(c, d1, None);
        let b1 = self.xor_rotate(b, c1, 24);
        let a2 = self.add(a1, b1, Some(y));
        let d2 = self.xor_rotate(d1, a2, 16);
        let c2 = self.add(c1, d2, None);
        let b2 = self.xor_rotate(b1, c2, 63);
        [a2, b2, c2, d2]
    }
}

fn build() -> (Blake2bGAir, Vec<Vec<M31>>, [u64; 4]) {
    let mut builder = Builder::new();
    let a = builder.word(0x6a09_e667_f3bc_c908);
    let b = builder.word(0xbb67_ae85_84ca_a73b);
    let c = builder.word(0x3c6e_f372_fe94_f82b);
    let d = builder.word(0xa54f_f53a_5f1d_36f1);
    let x = builder.word(0x510e_527f_ade6_82d1);
    let y = builder.word(0x9b05_688c_2b3e_6c1f);

    let a1 = builder.add(a, b, Some(x));
    let d1 = builder.xor_rotate(d, a1, 32);
    let c1 = builder.add(c, d1, None);
    let b1 = builder.xor_rotate(b, c1, 24);
    let a2 = builder.add(a1, b1, Some(y));
    let d2 = builder.xor_rotate(d1, a2, 16);
    let c2 = builder.add(c1, d2, None);
    let b2 = builder.xor_rotate(b1, c2, 63);

    let air = Blake2bGAir {
        log_size: LOG_SIZE,
        num_columns: builder.columns.len(),
        words: builder.words,
        ops: builder.ops,
        public_words: Vec::new(),
    };
    let output = [a2.value, b2.value, c2.value, d2.value];
    assert_eq!(
        output, BLAKE2B_G_KNOWN_OUTPUT,
        "Blake2b G witness must match its known-answer vector"
    );
    (air, builder.columns, output)
}

/// Build a full 12-round compression for the fixed 65-byte L1 leaf domain.
///
/// This is deliberately a wide-row validation baseline. It proves an actual
/// Blake2b-256 compression and pins the digest in AIR, but its direct Boolean
/// decomposition must be replaced by the lookup/interactions design before
/// it can be scaled to a sparse-Merkle path.
fn build_compression() -> (Blake2bGAir, Vec<Vec<M31>>, [u64; 4]) {
    const G_SCHEDULE: [[usize; 4]; 8] = [
        [0, 4, 8, 12],
        [1, 5, 9, 13],
        [2, 6, 10, 14],
        [3, 7, 11, 15],
        [0, 5, 10, 15],
        [1, 6, 11, 12],
        [2, 7, 8, 13],
        [3, 4, 9, 14],
    ];

    let witness = Blake2bSmtSingleBlock::leaf([0x11; 32], [0x22; 32]);
    let message_words = witness.message_words();
    let initialized_state = witness.initial_state_words();
    let digest = witness.native_digest();
    let expected_digest_words: [u64; 4] = std::array::from_fn(|index| {
        u64::from_le_bytes(
            digest[index * 8..(index + 1) * 8]
                .try_into()
                .expect("32-byte digest has four words"),
        )
    });

    let mut builder = Builder::new();
    let initial_words: [Word; 8] =
        std::array::from_fn(|index| builder.word(initialized_state[index]));
    let message: [Word; 16] = std::array::from_fn(|index| builder.word(message_words[index]));
    let mut state = [initial_words[0]; 16];
    state[..8].copy_from_slice(&initial_words);
    for index in 0..8 {
        state[index + 8] = builder.word(BLAKE2B_IV[index]);
    }
    // BLAKE2b's one final block carries the 65-byte counter in v12 and the
    // finalization flag in v14. These words are fully constrained by the G
    // transition trace, not selected by a host-side branch.
    state[12] = builder.word(BLAKE2B_IV[4] ^ witness.counter() as u64);
    state[13] = builder.word(BLAKE2B_IV[5] ^ (witness.counter() >> 64) as u64);
    state[14] = builder.word(!BLAKE2B_IV[6]);
    state[15] = builder.word(BLAKE2B_IV[7]);

    for sigma in poker_texas_air::blake2b_smt_witness::BLAKE2B_SIGMA {
        for (g_index, [a, b, c, d]) in G_SCHEDULE.into_iter().enumerate() {
            let [next_a, next_b, next_c, next_d] = builder.g(
                state[a],
                state[b],
                state[c],
                state[d],
                message[sigma[2 * g_index]],
                message[sigma[2 * g_index + 1]],
            );
            state[a] = next_a;
            state[b] = next_b;
            state[c] = next_c;
            state[d] = next_d;
        }
    }
    let final_words: [Word; 4] = std::array::from_fn(|index| {
        let mixed = builder.xor_rotate(state[index], state[index + 8], 0);
        builder.xor_rotate(initial_words[index], mixed, 0)
    });
    let mut public_words: Vec<_> = initial_words
        .iter()
        .copied()
        .zip(initialized_state)
        .collect();
    public_words.extend(message.iter().copied().zip(message_words));
    public_words.extend(final_words.into_iter().zip(expected_digest_words));

    let air = Blake2bGAir {
        log_size: LOG_SIZE,
        num_columns: builder.columns.len(),
        words: builder.words,
        ops: builder.ops,
        public_words,
    };
    (air, builder.columns, expected_digest_words)
}

fn evaluations(columns: &[Vec<M31>]) -> Vec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>> {
    let domain = CanonicCoset::new(LOG_SIZE).circle_domain();
    columns
        .iter()
        .map(|column| {
            CircleEvaluation::<SimdBackend, M31, NaturalOrder>::new(
                domain,
                BaseColumn::from_cpu(column),
            )
            .bit_reverse()
        })
        .collect()
}

fn main() {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    let compression_mode = arguments.iter().any(|arg| arg == "--compression");
    let tamper_output = arguments.iter().any(|arg| arg == "--tamper-output");
    assert!(
        !tamper_output || compression_mode,
        "--tamper-output requires --compression"
    );
    let (air, columns, output) = if compression_mode {
        build_compression()
    } else {
        build()
    };
    let mut allocator = TraceLocationAllocator::default();
    let component = FrameworkComponent::new(&mut allocator, air.clone(), SecureField::from(0u32));
    println!(
        "{}: columns={} constraints={} output={output:016x?}",
        if compression_mode {
            "blake2b-256-single-block"
        } else {
            "blake2b-g"
        },
        columns.len(),
        component.n_constraints(),
    );

    let config = PcsConfig {
        pow_bits: 2,
        fri_config: FriConfig::new(0, 1, 3, 1),
        lifting_log_size: None,
    };
    let twiddles = SimdBackend::precompute_twiddles(CanonicCoset::new(LOG_SIZE + 1).half_coset());
    let mut prover_channel = Poseidon252Channel::default();
    let mut scheme =
        CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::new(config, &twiddles);
    {
        let mut tree = scheme.tree_builder();
        tree.extend_evals(vec![]);
        tree.commit(&mut prover_channel);
    }
    {
        let mut tree = scheme.tree_builder();
        tree.extend_evals(evaluations(&columns));
        tree.commit(&mut prover_channel);
    }
    let start = Instant::now();
    let proof = prove(&[&component], &mut prover_channel, scheme)
        .expect("Blake2b G witness satisfies its AIR");
    let prove_ms = start.elapsed().as_secs_f64() * 1000.0;

    let mut verifier_channel = Poseidon252Channel::default();
    let mut verifier = CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
    verifier.commit(proof.commitments[0], &[], &mut verifier_channel);
    verifier.commit(
        proof.commitments[1],
        &vec![LOG_SIZE; columns.len()],
        &mut verifier_channel,
    );
    let mut allocator = TraceLocationAllocator::default();
    let mut verifier_air = air;
    if tamper_output {
        let (_, digest_word) = verifier_air
            .public_words
            .last_mut()
            .expect("compression mode has public digest words");
        *digest_word ^= 1;
    }
    let verifier_component =
        FrameworkComponent::new(&mut allocator, verifier_air, SecureField::from(0u32));
    let start = Instant::now();
    let result = verify(
        &[&verifier_component],
        &mut verifier_channel,
        &mut verifier,
        proof,
    );
    let verify_ms = start.elapsed().as_secs_f64() * 1000.0;
    if tamper_output {
        assert!(
            result.is_err(),
            "a proof must not verify against a changed public Blake2b digest"
        );
        println!("  tampered digest rejected after {verify_ms:.2} ms");
    } else {
        result.expect("Blake2b G witness satisfies its AIR");
        println!("  prove={prove_ms:.2} ms verify={verify_ms:.2} ms");
    }
}
