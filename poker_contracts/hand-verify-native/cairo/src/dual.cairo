// Vendored from poker_contracts/src/dual (spike copy; spike-local patches:
// `Zero::is_zero(@a)` disambiguation for corelib-2.19.4). Only the modules
// hand_verify needs are declared — keccak/secp/fr/hand_batch stay out so the
// deprecated corelib-internal-use warnings never enter the executable.
mod bg_stark;
mod hand_batch_stark;
mod hand_verify;
