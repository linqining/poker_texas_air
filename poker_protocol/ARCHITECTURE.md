# Poker protocol crate boundaries

Phase 1 separates protocol logic from the execution environment while keeping
`poker_protocol` as a compatibility facade.

```text
poker-protocol-abi          stable bytes / foreign-call interface
        ^
        |
poker_protocol::precompile native reference adapter (BLS12-381)

poker-protocol-core         curve traits, current curve backends, ElGamal,
        ^                   transcript interface, shared verification errors
        |
poker-protocol-bg           curve-generic Bayer-Groth proof
        ^
        |
poker-protocol-proofs       complete proof suite: shuffle, DLEQ, remask,
        ^                   leave, reveal-token, reconstruction and swap-out
        |
poker_protocol              compatibility facade, poker state machine and
                            client operations
        ^
        |
texas / client-wasm / client-wasm-aleo
```

## Dependency rules

- `poker-protocol-abi` has no elliptic-curve or chain dependency. STWO and a
  chain host should depend on this crate directly.
- `poker-protocol-core` contains reusable cryptographic primitives and the
  current Ristretto/BLS12-381 implementations. It contains no poker game state.
- `poker-protocol-bg` depends only on core and `rand_core`. It must not depend
  on Texas, Sui, STWO, or the facade.
- `poker-protocol-proofs` owns every proof type and its Borsh implementation.
  It depends on core and Bayer-Groth, but contains no table/game state.
- `poker_protocol` is a compatibility and application facade. Its
  `zk_shuffle::*` modules only re-export `poker-protocol-proofs`; proof
  implementations must not be added back to the facade.
- Application crates must not be dependencies of lower protocol layers.

## Proof ownership

| Game phase | Proof implementation |
| --- | --- |
| Player registration | `PKOwnershipProof` |
| Initial / repeated shuffle | `VersionedShuffleProof`, Bayer-Groth V2 |
| Join / mask | `RemaskProof`, `DLEqProof<RemaskKind>` |
| Leave | `LeaveProof`, `DLEqProof<LeaveKind>` |
| Card reveal | `RevealTokenProof` |
| Expel / reconstruction | `ReconstructProof`, `ReconstructionDLEQProof`, `ChaumPedersenDLEQProof` |
| Hand replacement | `SwapOutCardProof` |

All entries above are defined in `poker-protocol-proofs`. The old
`poker_protocol::zk_shuffle::<module>` paths remain source-compatible re-export
paths for the product gateway and WASM clients during the Aleo migration.

## M31 and BLS12-377

M31 is the STWO execution field; it is not the group used by the shuffle
argument. The circuit records a `ShuffleVerifyRequest` foreign/precompile call.
The host verifies the request using the `CurveId` selected by the request and
returns the constrained result.

The current native reference adapter accepts `CurveId::Bls12381G1`. The ABI
already reserves `CurveId::Bls12377G1`; adding the BLS12-377 backend belongs in
the precompile host/backend layer and does not require changing the STWO-facing
request layout.

This is a legacy compatibility boundary, not a host-zero cryptographic
verifier: a STWO proof that only commits a native verifier receipt still trusts
the party that issued that receipt. The Ristretto255 host-zero migration uses
a new versioned request/state domain and proves the cryptographic relations in
AIR; it must not reinterpret the BLS12-381 bytes in an existing table. See
`../HOST_ZERO_RISTRETTO_AIR.md` for the required circuit and admission gates.

## Wire compatibility

- Shuffle proof system id `2` means Bayer-Groth V2.
- ABI v1 uses canonical, length-prefixed little-endian framing and rejects
  unknown flags, invalid lengths, unsupported ids and trailing bytes.
- Legacy shuffle V1 is not represented in the precompile ABI and remains
  fail-closed in the facade verifier.
