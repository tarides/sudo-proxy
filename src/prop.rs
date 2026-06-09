//! Deterministic, dependency-free input generators for the property tests
//! (Rung 2 of the assurance ladder, see `docs/formalisation-roadmap.md`).
//!
//! Each security property elsewhere in the crate is written as a *named
//! predicate function* — a clause of the spec that takes an input and asserts
//! the invariant. This module supplies only the inputs that drive those
//! predicates in a `#[test]`. Keeping the generator separate from the
//! predicate is deliberate: Rung 3 can re-drive the very same predicate
//! functions with `kani::any()` instead of this PRNG without touching them.
//!
//! The PRNG is a fixed-seed xorshift64*: reproducible (a failing run replays
//! from its seed) and dependency-free (no proptest/quickcheck, which would
//! contribute nothing to the later formal rungs while enlarging the dependency
//! tree the Rung 1 `cargo deny` gate must vet).

/// Fixed-seed xorshift64* PRNG. The state update matches the closures that the
/// `fuzz_*` tests previously inlined, so a given seed reproduces the same byte
/// stream — coverage is preserved across the reframe.
pub struct Rng {
    state: u64,
}

impl Rng {
    /// Construct from a seed. xorshift64* degenerates on a zero state, so a
    /// zero seed is replaced with a fixed non-zero constant.
    pub fn new(seed: u64) -> Self {
        Self {
            state: if seed == 0 { 0x9E3779B97F4A7C15 } else { seed },
        }
    }

    /// Next 64-bit output. Mutates and returns the state (matching the prior
    /// inlined generators exactly).
    pub fn next_u64(&mut self) -> u64 {
        self.state ^= self.state >> 12;
        self.state ^= self.state << 25;
        self.state ^= self.state >> 27;
        self.state = self.state.wrapping_mul(0x2545F4914F6CDD1D);
        self.state
    }

    /// A value in `0..n`. `n` must be non-zero.
    pub fn below(&mut self, n: usize) -> usize {
        (self.next_u64() as usize) % n
    }

    /// A random string of length `0..=max_len`, each byte drawn uniformly from
    /// `alphabet` and pushed as a `char`. `alphabet` must be non-empty.
    pub fn string(&mut self, alphabet: &[u8], max_len: usize) -> String {
        let len = self.below(max_len + 1);
        let mut s = String::with_capacity(len);
        for _ in 0..len {
            s.push(alphabet[self.below(alphabet.len())] as char);
        }
        s
    }
}
