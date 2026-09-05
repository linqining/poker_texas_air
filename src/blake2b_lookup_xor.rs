//! Stwo 2.3 byte-XOR LogUp foundation for the BLAKE2b AIR port.
//!
//! The direct Blake2b SMT component deliberately uses Boolean decompositions
//! as its soundness-first implementation.  A 256-level L1 sparse-Merkle path
//! cannot use that representation economically.  This module is the smallest
//! independently proven building block of the replacement: it proves that
//! every active `(a, b, c)` row satisfies `c = a XOR b` for canonical bytes,
//! using a fixed 2^16 preprocessed table and a LogUp multiset relation.
//!
//! The full BLAKE2b port will use the same relation for the 32 byte XORs in
//! each 64-bit `G` invocation.  Keeping this component separate prevents a
//! generated-Cairo AIR dependency from silently pinning this workspace to an
//! incompatible Stwo revision.

#![allow(missing_docs)]

#[cfg(test)]
mod tests {
    use stwo::core::channel::{Channel, Poseidon252Channel};
    use stwo::core::fields::m31::M31;
    use stwo::core::fields::qm31::SecureField;
    use stwo::core::fri::FriConfig;
    use stwo::core::pcs::{CommitmentSchemeVerifier, PcsConfig};
    use stwo::core::poly::circle::CanonicCoset;
    use stwo::core::vcs_lifted::poseidon252_merkle::Poseidon252MerkleChannel;
    use stwo::core::verifier::verify;
    use stwo::prover::backend::simd::SimdBackend;
    use stwo::prover::backend::simd::column::BaseColumn;
    use stwo::prover::backend::simd::m31::LOG_N_LANES;
    use stwo::prover::backend::simd::qm31::PackedSecureField;
    use stwo::prover::pcs::CommitmentSchemeProver;
    use stwo::prover::poly::BitReversedOrder;
    use stwo::prover::poly::circle::{CircleEvaluation, PolyOps};
    use stwo::prover::{ComponentProver, prove};
    use stwo_constraint_framework::preprocessed_columns::PreProcessedColumnId;
    use stwo_constraint_framework::{
        EvalAtRow, FrameworkComponent, FrameworkEval, LogupTraceGenerator, Relation, RelationEntry,
        TraceLocationAllocator, relation,
    };

    // The full byte table has one row for each ordered pair `(a, b)`.  Keeping
    // its log size equal to the use trace makes this first roundtrip compact
    // and removes mixed-domain plumbing from the correctness test.  The
    // production G/round scheduler may use this same table at log size 16
    // while its use trace is larger.
    const LOG_SIZE: u32 = 16;
    const ROWS: usize = 1 << LOG_SIZE;
    const LOOKUP_ROWS: usize = 4096;

    relation!(Blake2bByteXor, 3);

    fn xor_ids() -> [PreProcessedColumnId; 3] {
        [
            PreProcessedColumnId {
                id: "blake2b.lookup.xor8.a.v1".into(),
            },
            PreProcessedColumnId {
                id: "blake2b.lookup.xor8.b.v1".into(),
            },
            PreProcessedColumnId {
                id: "blake2b.lookup.xor8.c.v1".into(),
            },
        ]
    }

    /// The table is verifier-reconstructed, not prover supplied.  Its i-th
    /// row is `(i >> 8, i & 0xff, (i >> 8) XOR (i & 0xff))`.
    fn preprocessed_xor_trace() -> Vec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>> {
        let domain = CanonicCoset::new(LOG_SIZE).circle_domain();
        let a = BaseColumn::from_iter((0..ROWS).map(|index| M31::from((index >> 8) as u32)));
        let b = BaseColumn::from_iter((0..ROWS).map(|index| M31::from((index & 0xff) as u32)));
        let c = BaseColumn::from_iter(
            (0..ROWS).map(|index| M31::from(((index >> 8) as u32) ^ ((index & 0xff) as u32))),
        );
        vec![
            CircleEvaluation::new(domain, a),
            CircleEvaluation::new(domain, b),
            CircleEvaluation::new(domain, c),
        ]
    }

    #[derive(Clone)]
    struct XorUseAir {
        elements: Blake2bByteXor,
    }

    impl FrameworkEval for XorUseAir {
        fn log_size(&self) -> u32 {
            LOG_SIZE
        }

        fn max_constraint_log_degree_bound(&self) -> u32 {
            LOG_SIZE + 1
        }

        fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
            let a = eval.next_trace_mask();
            let b = eval.next_trace_mask();
            let c = eval.next_trace_mask();
            let active = eval.next_trace_mask();
            let one: E::F = M31::from(1u32).into();
            eval.add_constraint(active.clone() * (active.clone() - one.clone()));
            // Inactive rows must not hide arbitrary values in the committed
            // trace.  Active values are range-bound by the table relation.
            let inactive = one - active.clone();
            for value in [&a, &b, &c] {
                eval.add_constraint(inactive.clone() * value.clone());
            }
            eval.add_to_relation(RelationEntry::new(
                &self.elements,
                E::EF::from(active),
                &[a, b, c],
            ));
            eval.finalize_logup_in_pairs();
            eval
        }
    }

    #[derive(Clone)]
    struct XorTableAir {
        elements: Blake2bByteXor,
    }

    impl FrameworkEval for XorTableAir {
        fn log_size(&self) -> u32 {
            LOG_SIZE
        }

        fn max_constraint_log_degree_bound(&self) -> u32 {
            LOG_SIZE + 1
        }

        fn evaluate<E: EvalAtRow>(&self, mut eval: E) -> E {
            let [a_id, b_id, c_id] = xor_ids();
            let a = eval.get_preprocessed_column(a_id);
            let b = eval.get_preprocessed_column(b_id);
            let c = eval.get_preprocessed_column(c_id);
            let multiplicity = eval.next_trace_mask();
            eval.add_to_relation(RelationEntry::new(
                &self.elements,
                -E::EF::from(multiplicity),
                &[a, b, c],
            ));
            eval.finalize_logup_in_pairs();
            eval
        }
    }

    struct XorWitness {
        // Original-trace columns in `XorUseAir` order.
        uses: [BaseColumn; 4],
        // Original-trace column in `XorTableAir` order.
        multiplicities: BaseColumn,
    }

    impl XorWitness {
        fn new() -> Self {
            let mut a = vec![M31::from(0u32); ROWS];
            let mut b = vec![M31::from(0u32); ROWS];
            let mut c = vec![M31::from(0u32); ROWS];
            let mut active = vec![M31::from(0u32); ROWS];
            let mut multiplicities = vec![M31::from(0u32); ROWS];

            // Use enough distinct rows to exercise nontrivial multiplicities,
            // while retaining zero padding that the AIR has to constrain.
            for row in 0..LOOKUP_ROWS {
                let left = ((row * 73 + 19) & 0xff) as u8;
                let right = ((row * 151 + 7) & 0xff) as u8;
                let result = left ^ right;
                a[row] = M31::from(u32::from(left));
                b[row] = M31::from(u32::from(right));
                c[row] = M31::from(u32::from(result));
                active[row] = M31::from(1u32);
                let table_row = (usize::from(left) << 8) | usize::from(right);
                multiplicities[table_row] += M31::from(1u32);
            }
            Self {
                uses: [
                    BaseColumn::from_cpu(&a),
                    BaseColumn::from_cpu(&b),
                    BaseColumn::from_cpu(&c),
                    BaseColumn::from_cpu(&active),
                ],
                multiplicities: BaseColumn::from_cpu(&multiplicities),
            }
        }

        fn original_trace(&self) -> Vec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>> {
            let domain = CanonicCoset::new(LOG_SIZE).circle_domain();
            self.uses
                .iter()
                .chain(std::iter::once(&self.multiplicities))
                .cloned()
                .map(|column| CircleEvaluation::new(domain, column))
                .collect()
        }

        fn use_interaction_trace(
            &self,
            elements: &Blake2bByteXor,
        ) -> (
            Vec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>>,
            SecureField,
        ) {
            let mut generator = LogupTraceGenerator::new(LOG_SIZE);
            let mut column = generator.new_col();
            for vec_row in 0..(1usize << (LOG_SIZE - LOG_N_LANES)) {
                let tuple = [
                    self.uses[0].data[vec_row],
                    self.uses[1].data[vec_row],
                    self.uses[2].data[vec_row],
                ];
                let denominator: PackedSecureField = elements.combine(&tuple);
                let numerator = PackedSecureField::from(self.uses[3].data[vec_row]);
                column.write_frac(vec_row, numerator, denominator);
            }
            column.finalize_col();
            generator.finalize_last()
        }

        fn table_interaction_trace(
            &self,
            elements: &Blake2bByteXor,
        ) -> (
            Vec<CircleEvaluation<SimdBackend, M31, BitReversedOrder>>,
            SecureField,
        ) {
            // Reconstruct the verifier-owned table in the prover solely to
            // read its packed values. `BaseColumn::from_iter` performs the
            // packing internally, which keeps this crate's unsafe-code ban
            // intact and does not require the portable-SIMD feature here.
            let table_a =
                BaseColumn::from_iter((0..ROWS).map(|index| M31::from((index >> 8) as u32)));
            let table_b =
                BaseColumn::from_iter((0..ROWS).map(|index| M31::from((index & 0xff) as u32)));
            let table_c = BaseColumn::from_iter(
                (0..ROWS).map(|index| M31::from(((index >> 8) as u32) ^ ((index & 0xff) as u32))),
            );
            let mut generator = LogupTraceGenerator::new(LOG_SIZE);
            let mut column = generator.new_col();
            for vec_row in 0..(1usize << (LOG_SIZE - LOG_N_LANES)) {
                let tuple = [
                    table_a.data[vec_row],
                    table_b.data[vec_row],
                    table_c.data[vec_row],
                ];
                let denominator: PackedSecureField = elements.combine(&tuple);
                let numerator = PackedSecureField::from(-self.multiplicities.data[vec_row]);
                column.write_frac(vec_row, numerator, denominator);
            }
            column.finalize_col();
            generator.finalize_last()
        }
    }

    fn config() -> PcsConfig {
        PcsConfig {
            pow_bits: 2,
            fri_config: FriConfig::new(0, 1, 8, 1),
            lifting_log_size: Some(LOG_SIZE + 1 + 1),
        }
    }

    #[ignore = "slow prove (~12s); full gate runs `--include-ignored`"]
    #[test]
    fn byte_xor_logup_table_proves_and_rejects_a_modified_relation() {
        let witness = XorWitness::new();
        let config = config();
        let twiddles = crate::prover_context::simd_twiddles(
            LOG_SIZE + 1 + config.fri_config.log_blowup_factor,
        );
        let mut channel = Poseidon252Channel::default();
        let mut scheme =
            CommitmentSchemeProver::<SimdBackend, Poseidon252MerkleChannel>::new(config, &twiddles);
        {
            let mut tree = scheme.tree_builder();
            tree.extend_evals(preprocessed_xor_trace());
            tree.commit(&mut channel);
        }
        {
            let mut tree = scheme.tree_builder();
            tree.extend_evals(witness.original_trace());
            tree.commit(&mut channel);
        }
        let elements = Blake2bByteXor::draw(&mut channel);
        let (uses_interaction, uses_sum) = witness.use_interaction_trace(&elements);
        let (table_interaction, table_sum) = witness.table_interaction_trace(&elements);
        assert_eq!(uses_sum + table_sum, SecureField::from(0u32));
        channel.mix_felts(&[uses_sum, table_sum]);
        {
            let mut tree = scheme.tree_builder();
            tree.extend_evals(
                uses_interaction
                    .into_iter()
                    .chain(table_interaction)
                    .collect(),
            );
            tree.commit(&mut channel);
        }
        let ids = xor_ids();
        let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
        let use_component = FrameworkComponent::new(
            &mut allocator,
            XorUseAir {
                elements: elements.clone(),
            },
            uses_sum,
        );
        let table_component = FrameworkComponent::new(
            &mut allocator,
            XorTableAir {
                elements: elements.clone(),
            },
            table_sum,
        );
        let proof = prove(
            &[
                &use_component as &dyn ComponentProver<SimdBackend>,
                &table_component as &dyn ComponentProver<SimdBackend>,
            ],
            &mut channel,
            scheme,
        )
        .expect("lookup witness must satisfy byte-XOR AIR");

        let mut verifier_channel = Poseidon252Channel::default();
        let mut verifier = CommitmentSchemeVerifier::<Poseidon252MerkleChannel>::new(config);
        verifier.commit(
            proof.commitments[0],
            &vec![LOG_SIZE; 3],
            &mut verifier_channel,
        );
        verifier.commit(
            proof.commitments[1],
            &vec![LOG_SIZE; 5],
            &mut verifier_channel,
        );
        let verifier_elements = Blake2bByteXor::draw(&mut verifier_channel);
        verifier_channel.mix_felts(&[uses_sum, table_sum]);
        verifier.commit(
            proof.commitments[2],
            // Each Logup column is a SecureField column and is committed as
            // four M31 coordinate columns.  There are two lookup columns.
            &vec![LOG_SIZE; 8],
            &mut verifier_channel,
        );
        let mut allocator = TraceLocationAllocator::new_with_preprocessed_columns(&ids);
        let verifier_use_component = FrameworkComponent::new(
            &mut allocator,
            XorUseAir {
                elements: verifier_elements.clone(),
            },
            uses_sum,
        );
        let verifier_table_component = FrameworkComponent::new(
            &mut allocator,
            XorTableAir {
                elements: verifier_elements,
            },
            table_sum,
        );
        verify(
            &[&verifier_use_component, &verifier_table_component],
            &mut verifier_channel,
            &mut verifier,
            proof,
        )
        .expect("lookup proof verifies");
    }
}
