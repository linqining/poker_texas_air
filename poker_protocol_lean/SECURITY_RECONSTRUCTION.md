# Reconstruction security statement and formal-proof boundary

Status date: 2026-08-02

This document is the security appendix for the reconstruction phase of
`poker-protocol-proofs`. It is written to be citable from a paper and to make
the machine-checked boundary explicit.

## 1. Executive result

The legacy Rust reconstruction-v2 protocol does **not** satisfy the claimed
soundness or zero-knowledge definitions. It remains a compatibility type and
counterexample target, not the production security basis. Rust
`ReconstructProofV3` implements the repaired relation with aggregate-key
contributions, joint cross-key proofs, Bayer--Groth hidden permutation,
per-slot OR proofs and state/version transcript binding.

The Lean development now contains:

1. machine-checked counterexamples against the v2 statement;
2. a machine-checked provenance theorem for `user_readable_cards`;
3. a repaired reconstruction-v3 extracted relation;
4. machine-checked deterministic completeness and semantic soundness of that
   relation;
5. a concrete algebraic formalization of the V3 slot OR protocol, including
   completeness, fork extraction and its perfect-HVZK change of variables;
6. a PK-ownership specialization of generalized Schnorr;
7. conditional end-to-end completeness, knowledge-soundness and
   computational-ZK theorems exposing every remaining Bayer--Groth,
   Fiat--Shamir, serialization and state-machine obligation.

The old top-level `Unit` witness / `True` relation has been removed. It proved
security only for a verifier that always accepted and was unrelated to Rust.

## 2. Meaning and provenance of `user_readable_cards`

`user_readable_cards` are the owner's still-encrypted private cards from the
previous hand/round. They are not freshly chosen reconstruction inputs and are
not literally byte-for-byte entries of `init_deck`.

Their authenticated lineage is:

```text
canonical init_deck card (g, card_i)
  -> proved player-key masking
  -> proved re-encryption and shuffle rounds
  -> authenticated prior-hand assignment
  -> valid reveal tokens from every non-owner player
  -> R_i = Enc_pk_owner(card_i; r_i)
```

The Rust initial representation `(g, card_i)` is exactly
`Enc_0(card_i; 1)`. If a ciphertext is `Enc_pk(m; r)`, a joining player with
secret key `x` first changes the key to `pk + x*g`, then re-randomizes by
`rho`, yielding `Enc_(pk+x*g)(m; r+rho)`. After other players' valid reveal
tokens are subtracted, the owner receives `Enc_pk_owner(m; r)`.

The following Lean theorems establish this algebra:

- `initialCard_eq_encrypt_zero_key`;
- `remask_extends_aggregate_key`;
- `joinStep_preserves_plaintext`;
- `lineage_is_canonical_encryption`;
- `partial_decryption_yields_owner_ciphertext`;
- `authenticated_prior_hand_yields_user_readable_card`;
- `user_readable_c1_eq_accumulated_randomness`.

The formal source is
`PokerProtocolLean/Reconstruct/ReadableCardProvenance.lean`.

### Protocol-state assumptions for provenance

The algebraic theorem is conditional on authenticated transitions. A concrete
implementation must enforce all of the following:

- every initial plaintext is a unique canonical card point;
- every remask transition has an accepted proof under the registered key;
- every shuffle transition is an accepted permutation/re-encryption proof;
- prior-hand assignments are immutable and authenticated by the state machine;
- every subtracted reveal token has a valid DLEQ proof and is bound to the same
  dealt ciphertext;
- all non-owner shares, and no owner share, are removed;
- readable sets of different players are disjoint within one reconstruction
  epoch.

Reconstruction alone cannot infer these historical facts. The precompile/AIR
interface must bind a reconstruction statement to the state root or digest
that authenticates this lineage.

## 3. Why the readable-card discrete logarithm is unknown

For a valid readable card,

```text
R_i.c1 = r_i * g
R_i.c2 = card_i + r_i * pk_owner.
```

The privacy requirement is that `r_i` is unknown to the adversary. This is a
distributional statement, not a worst-case statement about every fixed group
point. In particular, a hypothesis saying “the discrete logarithm of every
point is hard” is false because `DL_g(g) = 1` is public.

The correct assumption is the average-case experiment:

```text
r <- uniform F
A(g, r*g) -> r'
win iff r' = r.
```

`Foundations.UnknownDiscreteLog.FreshDLogHard` now wraps VCV-io's standard
`DiffieHellman.dlogExp`. The older pointwise `UnknownDL(P)` remains only as a
conditional notion and the old all-points premise is marked non-standard.

To apply `FreshDLogHard` to `R_i.c1`, the protocol needs at least one honest,
secret, uniformly random re-randomizer in the authenticated shuffle lineage.
Adding any adversarially known offset to that honest uniform scalar preserves
uniformity. Lean theorem `honest_rerandomizer_translation_bijective` proves the
required scalar-field change of variables. The concrete paper theorem must
state the corruption model and identify which shuffle supplies this entropy.

Unknown `DL(R_i.c1)` is needed for confidentiality: if `r_i` is known, anyone
computes `card_i = R_i.c2 - r_i*pk_owner`. It is **not** needed for the
cross-key plaintext-negation soundness equation described below.

## 4. Machine-checked failures of Rust reconstruction v2

### 4.1 Misplaced-swap soundness attack

The v2 verifier proves that `padded_swap_cards` is a Bayer--Groth shuffle of
the swap ciphertexts plus zero ciphertexts and that

```text
output[i] + padded[i] = Enc_pk_user(cards[i]).
```

It does not bind the plaintext of `padded[i]` to `cards[i]`. For distinct
nonzero cards `A` and `B`, an adversarial witness can set

```text
padded[i] = Enc(A; s)
output[i] = Enc(B - A; r).
```

Then `output[i] + padded[i] = Enc(B; r+s)`, so the corrected ordered-encryption
check passes, while `B-A` is neither zero nor `B`.

Lean theorems:

- `misplaced_swap_satisfies_corrected_relation`;
- `misplaced_output_is_not_an_honest_branch`.

This attack does not solve a discrete logarithm. Public group subtraction
computes `B-A` directly.

### 4.2 Public-randomness zero-knowledge failure

Rust derives output randomness as public powers of `coefficient`. For any
ElGamal ciphertext whose randomness `r` is public,

```text
ct.c2 - r*pk = plaintext.
```

Thus observers distinguish a zero-output slot from a card-output slot and
learn the previous private-hand indices.

Lean theorems:

- `recover_plaintext_from_known_randomness`;
- `public_randomness_reveals_branch`.

Consequently v2 is not computational ZK, honest-verifier ZK, witness
indistinguishable, or even plaintext hiding for this public statement.

### 4.3 Multi-player aggregation mismatch

Each v2 player encrypts under a different `user_pk`. Adding ciphertexts that
reuse the same public scalar `r` yields a first component `(r+r)*g` but a key
term `r*(pk1+pk2)`. This is not the standard ElGamal form under the aggregate
key with a single matching exponent, except in degenerate cases.

Lean theorem `same_randomness_cross_key_sum_shape` records this exact shape.
The chain reconstruction formula must not sum per-user-key v2 outputs as if
they were ordinary ciphertexts under one aggregate key.

## 5. Repaired reconstruction-v3 relation

Every player publishes one contribution ciphertext per canonical slot under
the common aggregate key:

```text
contribution[i] = Enc_PKagg(0; v_i)
               OR Enc_PKagg(-cards[i]; v_i).
```

The branch, `v_i`, readable-card mapping and Bayer--Groth permutation remain
witness data. They do not appear in the public response.

For every negative branch there must be exactly one authenticated readable
card whose canonical plaintext is `cards[i]`. The witness mapping is
injective and satisfies exact coverage:

```text
removed[i] <-> exists unique j, readableIndex[j] = i.
```

The Lean `V3.Witness` and `V3.Relation` encode these requirements.

### 5.1 Cross-key joint linear proof

For readable `R = Enc_pk_owner(m; r)` and aggregate-key contribution
`S = Enc_PKagg(-m; v)`, prove knowledge of `(sk_owner, v)` satisfying

```text
pk_owner = sk_owner * g
S.c1 = v * g
sk_owner * R.c1 + v * PKagg = R.c2 + S.c2.
```

This is one generalized Schnorr relation with a genuinely shared witness. It
does not reveal `r`, the coefficient responses, the card index or the hidden
permutation. It also does not require knowledge of `DL(R.c1)`.

Lean theorems:

- `cross_key_negation_complete`;
- `cross_key_negation_binds_plaintexts`.

`ReconstructionV3JointSigma.lean` encodes all three equations as one
two-witness generalized Schnorr statement over `G x G x G`. The adapter theorem
`relation_iff_cross_key` is machine checked, and the concrete Sigma protocol
inherits machine-checked:

- perfect completeness (`JointSigma.sigma_complete`);
- special soundness (`JointSigma.sigma_speciallySound`);
- perfect HVZK (`JointSigma.sigma_perfect_hvzk`).

### 5.2 Slot OR proof

The misplaced-swap attack is prevented only if each canonical slot has a ZK OR
proof of plaintext membership `{0, -cards[i]}` under `PKagg`. Bayer--Groth
alone proves a multiset permutation and is insufficient for this per-slot
semantic binding.

The extracted OR branch is represented by `V3.Witness.removed`. Lean proves:

- `accepted_contribution_is_zero_or_negative_card`;
- `removed_iff_has_readable_witness`;
- `readable_indices_are_unique`.

`ReconstructionV3SlotOr.lean` additionally formalizes the concrete two-branch
verification equations used by Rust and proves:

- honest interactive acceptance (`SlotOr.honest_accepts`);
- two-fork special-sound extraction (`SlotOr.specially_sound`);
- accepting simulation without a witness (`SlotOr.simulate_accepts`);
- exact honest/simulated transcript reconstruction
  (`SlotOr.honest_eq_simulate`);
- the response-translation bijection used for perfect HVZK
  (`SlotOr.response_translation_bijective`).

### 5.3 Reconstruction correctness

Start from a canonical aggregate-key encryption of `cards[i]` and add all
players' contributions.

- if no prior hand contains `cards[i]`, all contributions encrypt zero and the
  plaintext remains `cards[i]`;
- if exactly one authenticated prior hand contains it, exactly one contribution
  encrypts `-cards[i]` and the plaintext becomes zero.

Lean theorems:

- `corrected_slot_semantics`;
- `aggregatePlaintext_no_removal`;
- `aggregatePlaintext_unique_removal`.

## 6. Security definitions and results

### 6.1 Adversary and corruption model

The intended theorem is for a probabilistic polynomial-time adversary in the
random-oracle model. The adversary may control any subset of players and all
network scheduling, but the theorem requires:

- the owner secret key of each challenged prior private card remains hidden;
- at least one authenticated shuffle in that card's lineage contributes an
  honest, secret, uniform re-randomizer;
- the state machine authenticates registration keys, prior hand assignments,
  accepted shuffle/remask/reveal transitions and reconstruction epochs;
- readable-card sets assigned to distinct players in one epoch are disjoint;
- the concrete curve implementation enforces prime-order subgroup membership
  and canonical decoding.

The zero-knowledge statement hides the owner-readable-to-canonical mapping,
the slot branch, all ElGamal randomness and the Bayer--Groth permutation. It
does not hide public deck size, number of readable cards, public keys,
canonical card points, contribution ciphertexts or authenticated state
digests.

### 6.2 Completeness

For every well-formed V3 statement and valid witness, an honest prover must
produce a proof accepted by the exact Rust verifier with probability one,
apart from explicit resampling of forbidden zero/identity encodings.

Machine-checked components are:

- `V3.valid_relation_complete`: fail-closed public validity plus honest
  encryption equations establishes the complete algebraic statement;
- `JointSigma.sigma_complete`: perfect completeness of the shared cross-key
  proof;
- `SlotOr.honest_accepts`: perfect interactive completeness of each slot OR
  proof;
- readable-card provenance and single-/multi-player reconstruction algebra.

`Security.completeness_under_assumptions` lifts these facts to the exact Rust
proof package under Bayer--Groth completeness and Rust/Lean transcript
refinement hypotheses.

### 6.3 Knowledge soundness

The knowledge-soundness game gives an adversary the public statement and
random-oracle access. If it outputs an accepting proof, a rewinding extractor
must output a V3 witness except with negligible probability. The extracted
witness must satisfy:

```text
each contribution[i] encrypts 0 or -cards[i]
and
removed[i] iff exactly one authenticated readable card maps to i.
```

Concrete machine-checked steps are:

- `JointSigma.sigma_speciallySound` extracts the same owner key and
  contribution randomness from two forks;
- `SlotOr.specially_sound` proves that two accepting OR transcripts with common
  commitments and different global challenges have a differing branch share
  and extract that branch's randomness;
- `accepted_contribution_is_zero_or_negative_card`,
  `removed_iff_has_readable_witness` and `readable_indices_are_unique` derive
  the semantic reconstruction relation;
- `Security.knowledge_soundness_under_assumptions` packages the exact Rust
  conclusion under Bayer--Groth extraction, ROM forking, transcript binding,
  serialization refinement and authenticated-state hypotheses.

### 6.4 Zero knowledge

V2 is not zero knowledge, as shown by the public-randomness recovery theorem.

For V3, the real and simulated non-interactive views must be computationally
indistinguishable in the random-oracle model. Machine-checked simulator facts
are:

- perfect HVZK of generalized Schnorr, Chaum--Pedersen, batched DLEQ, public-key
  ownership and the joint cross-key proof;
- `SlotOr.simulate_accepts`: both OR branches can be simulated from challenge
  shares and responses without a witness;
- `SlotOr.honest_eq_simulate`: the honest transcript equals the reconstructed
  simulator transcript pointwise;
- `SlotOr.response_translation_bijective`: the real response is a uniformity-
  preserving field translation;
- `SlotOr.perfect_hvzk_algebraic`: the complete algebraic HVZK package.

`Security.zero_knowledge_under_assumptions` gives the end-to-end conditional
theorem. Its unmechanized premises are the exact Bayer--Groth simulator,
shared-transcript sequential composition, Fiat--Shamir programming/forking and
byte-level Rust refinement. No witness index or `coefficient_responses` field
appears in the V3 response.

## 7. Implemented Rust V3 controls

`poker-protocol-proofs/src/reconstruction/v3.rs` and its component modules now
implement:

1. a versioned statement with context digest, monotonic reconstruction epoch
   and authenticated prior-state digest;
2. common aggregate-key contributions for all players;
3. contribution plaintexts restricted to `0` or `-cards[i]`;
4. a genuinely shared two-response cross-key proof for each readable card;
5. Bayer--Groth permutation/re-randomization to hide readable placement;
6. a per-canonical-slot witness-hiding OR proof;
7. exact length, non-empty, key, ciphertext, identity and unique-card checks;
8. witness/key consistency checks in prover APIs;
9. domain-separated component transcripts with all public statement fields and
   commitments appended before challenges;
10. fail-closed legacy shuffle dispatch.

The Rust integration now commits to those values. `poker_l1` accepts only the
V3 statement/proof pair and recomputes from the authenticated pre-state:

- aggregate and owner public keys;
- the fixed `init_deck` plaintext point vector;
- `reconstruct_started_at` as the reconstruction epoch;
- the exact owner-readable ciphertext vector stored in `decrypted_cards`; and
- a domain-separated prior-state digest covering table/hand/seat, aggregate
  key, plaintext lineage, readable-card indices and ciphertexts.

`poker_texas_air` encodes the same statement in the canonical V3 precompile
request and constrains the complete 256-bit request and receipt digests as
sixteen u16/M31 limbs each. Its stage-4 `outer_precompile` additionally binds
complete 256-bit aggregate and externally authenticated anchor digests, carries
the exact replayable tasks, re-verifies every child in O(N), and proves the
resulting receipt binding in a final STWO AIR. This is a transferable
host-verified precompile package, not succinct recursion.

Cross-player readable-set disjointness remains a state-machine invariant, not
something one player's proof can establish alone. The implemented VM path
relies on the authenticated shuffle/deal/reveal lineage for that invariant.

## 8. Rust--Lean theorem map

| Rust component | Public relation / check | Lean module and principal theorem |
| --- | --- | --- |
| `PKOwnershipProof` | `pk = sk*G` | `PKOwnership.generalized_relation_iff`, `sigma_complete`, `sigma_speciallySound`, `sigma_perfect_hvzk` |
| `DLEqProof<RemaskKind/LeaveKind>` | strict statement validity plus one shared key across all cards | `DLEq.WellFormedStatement`, `RustRelation`, `sigma_complete`, `sigma_speciallySound`, `sigma_perfect_hvzk` |
| `RevealTokenProof` | `pk = sk*G`, `token = sk*c1` | `RevealTokenProof.lean` via Chaum--Pedersen |
| `CrossKeyNegationProof` | three equations sharing `(ownerSk, v)` | `ReconstructionV3JointSigma.relation_iff_cross_key` and inherited Σ theorems |
| `SlotContributionOrProof` | `Enc(0;v) OR Enc(-card[i];v)` | `ReconstructionV3SlotOr.honest_accepts`, `specially_sound`, `perfect_hvzk_algebraic` |
| `ReconstructProofV3` extracted semantics | exact coverage and injective hidden mapping | `ReconstructionV3.Relation`, `valid_relation_complete`, semantic soundness theorems |
| production V3 package | BG + joint proofs + slot OR + shared FS transcript | `ReconstructionV3Security.*_under_assumptions` |
| authenticated prior hand | canonical `init_deck` plaintext lineage to owner ciphertext | `ReadableCardProvenance.authenticated_prior_hand_yields_user_readable_card` |

## 9. Trusted computing base and proof coverage

Machine checked with zero `sorry`/`admit`:

- v2 soundness and privacy counterexamples;
- initial-deck/readable-card provenance algebra;
- bijectivity of adding one honest re-randomizer to an adversarially known
  accumulated offset;
- V3 public well-formedness and extracted relation completeness;
- V3 exact-coverage, uniqueness and aggregation semantics;
- joint cross-key perfect completeness, special soundness and perfect HVZK;
- slot OR honest acceptance, fork extraction, simulator acceptance, exact
  transcript reconstruction and response-translation bijection;
- public-key ownership as one-base generalized Schnorr;
- conditional end-to-end completeness, knowledge-soundness and ZK theorem
  interfaces with all assumptions explicit.

Remaining linking obligations:

- mechanized correspondence between Rust serialization/transcript bytes and
  Lean statements;
- a formalization or verified refinement of the exact `poker-protocol-bg`
  Bayer--Groth implementation;
- a full shared-transcript Fiat--Shamir ROM extraction and simulation proof;
- a machine-checked Rust--Lean refinement proof that the implemented
  AIR/precompile digest binding matches the authenticated poker state
  transition (the Rust implementation and adversarial tests now exist);
- a machine-checked refinement of state-machine provenance and cross-player
  disjointness (the Rust VM now enforces the per-player V3 prior-hand binding);
- curve implementation, canonical decoding and subgroup-check correctness.

Therefore the publishable claim is: the repaired V3 algebraic relation and its
joint/OR Σ components are mechanized; end-to-end Rust non-interactive security
is a conditional theorem under explicitly enumerated Bayer--Groth, ROM,
serialization and authenticated-state assumptions. It is not an unconditional
verification of the complete production binary, and no such claim should be
made for legacy V2.
