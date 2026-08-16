use crate::Curve;

/// Transcript interface consumed by curve-generic proof systems.
///
/// Concrete transcript state machines remain backend policy. This separation
/// lets native SHA3, Merlin test transcripts, STWO hints, and a precompile host
/// implement the same challenge schedule.
pub trait CryptoTranscript {
    fn new(protocol_name: &[u8]) -> Self;
    fn append_message(&mut self, label: &[u8], message: &[u8]);
    fn challenge_bytes(&mut self, label: &[u8], dest: &mut [u8]);
    fn append_point<C: Curve>(&mut self, label: &[u8], point: &C::Point);
    fn append_scalar<C: Curve>(&mut self, label: &[u8], scalar: &C::Scalar);
    fn challenge<C: Curve>(&mut self, label: &[u8]) -> Challenge<C>;

    fn challenge_vec<C: Curve>(&mut self, label: &[u8], n: usize) -> Vec<C::Scalar> {
        (0..n)
            .map(|i| {
                let mut sub_label = label.to_vec();
                sub_label.extend_from_slice(i.to_string().as_bytes());
                self.challenge::<C>(&sub_label).scalar
            })
            .collect()
    }
}

#[derive(Debug, Clone)]
pub struct Challenge<C: Curve> {
    pub scalar: C::Scalar,
}
