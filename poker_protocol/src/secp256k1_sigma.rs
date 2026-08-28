//! SECP256K1 direct-sigma settlement route (DUAL_PROOF_PROTOCOL.md §3.1/§D1(v2.2)).
//!
//! Owns the canonical card derivation for the SECP256K1 G1 epoch and re-exports
//! the curve for downstream consumers. Cards are deterministically derived
//! with the same domain separation as the Ristretto route
//! (`texas_poker/card/{i}`), mapped into SECP256K1 G1 through the halo2curves
//! RFC 9380 SVDW suite. The contract side embeds the same 52 points as
//! immutable constants — no on-chain hash-to-curve is needed.

use poker_protocol_core::{Secp256k1Curve, Curve, CurvePoint};

/// Deck size for the SECP256K1 sigma epoch (standard 52-card deck).
pub const SECP256K1_TEXAS_DECK_SIZE: usize = 52;

/// Protocol label for canonical card derivation. Must match the Cairo
/// verifier's constant table generation script byte-for-byte.
pub const SECP256K1_CARD_DOMAIN: &[u8] = b"texas_poker_secp256k1/card/";

/// Return one canonical SECP256K1 G1 card point.
pub fn canonical_card(index: usize) -> Option<<Secp256k1Curve as Curve>::Point> {
    if index >= SECP256K1_TEXAS_DECK_SIZE {
        return None;
    }
    Some(Secp256k1Curve::hash_to_curve(card_label(index).as_bytes()))
}

/// Compressed SEC1 wire encoding of one canonical card point (33 bytes).
pub fn canonical_card_bytes(index: usize) -> Option<[u8; 33]> {
    let point = canonical_card(index)?;
    let mut out = [0u8; 33];
    out.copy_from_slice(point.compress().as_ref());
    Some(out)
}

/// The full canonical card table in deck order.
pub fn canonical_deck() -> Vec<<Secp256k1Curve as Curve>::Point> {
    (0..SECP256K1_TEXAS_DECK_SIZE).map(|i| canonical_card(i).expect("index < deck size")).collect()
}

fn card_label(index: usize) -> String {
    format!("{}{index}", String::from_utf8_lossy(SECP256K1_CARD_DOMAIN))
}

#[cfg(test)]
mod tests {
    use super::*;
    use poker_protocol_core::{CurvePoint, CurveScalar, ElGamalCiphertextGeneric};
    use rand_core::OsRng;

    #[test]
    fn card_table_is_deterministic_and_injective() {
        let deck = canonical_deck();
        assert_eq!(deck.len(), SECP256K1_TEXAS_DECK_SIZE);
        for (i, card) in deck.iter().enumerate() {
            assert_eq!(
                &canonical_card(i).expect("in-range index"),
                card,
                "card {i} must be deterministic"
            );
            assert!(
                !<Secp256k1Curve as Curve>::Point::is_identity(card),
                "card {i} must not be the identity point"
            );
        }
        let mut distinct = deck.clone();
        distinct.sort_by_key(|p| <Secp256k1Curve as Curve>::Point::compress(p).as_ref().to_vec());
        let n = distinct.len();
        distinct.dedup();
        assert_eq!(distinct.len(), n, "all 52 card points must be distinct");

        // Out-of-range indices are rejected.
        assert!(canonical_card(SECP256K1_TEXAS_DECK_SIZE).is_none());
        assert!(canonical_card_bytes(SECP256K1_TEXAS_DECK_SIZE).is_none());
    }

    #[test]
    fn card_bytes_are_33_byte_roundtrip() {
        for i in 0..SECP256K1_TEXAS_DECK_SIZE {
            let bytes = canonical_card_bytes(i).expect("in-range index");
            assert_eq!(bytes.len(), 33);
            let decoded = <Secp256k1Curve as Curve>::Point::from_compressed(&bytes)
                .expect("canonical card bytes decode");
            assert_eq!(decoded, canonical_card(i).unwrap());
        }
    }

    #[test]
    fn elgamal_over_card_deck_roundtrips() {
        // Aggregate-key mental poker over the canonical deck: encrypt under
        // a random aggregate key, decrypt back to the exact card points.
        let sk = <Secp256k1Curve as Curve>::Scalar::random(&mut OsRng);
        let pk = Secp256k1Curve::base_g() * &sk;
        let deck = canonical_deck();

        let ciphertexts: Vec<ElGamalCiphertextGeneric<Secp256k1Curve>> = deck
            .iter()
            .map(|card| {
                let r = <Secp256k1Curve as Curve>::Scalar::random(&mut OsRng);
                ElGamalCiphertextGeneric::<Secp256k1Curve>::encrypt(card, &pk, &r)
            })
            .collect();

        for (ct, card) in ciphertexts.iter().zip(&deck) {
            assert_eq!(&ct.decrypt(&sk), card);
        }
    }
}
