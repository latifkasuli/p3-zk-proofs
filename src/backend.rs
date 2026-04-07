//! Proving and verification backend configurations.
//!
//! Two backends are provided:
//!
//! | Backend | PCS | Blinding | Intended use |
//! |---|---|---|---|
//! | [`StandardBackend`] | `TwoAdicFriPcs` | None | Fast, non-private proofs |
//! | [`HidingBackend`] | `HidingFriPcs` | CSPRNG-salted Merkle leaves + randomizer columns | ZK proofs |
//!
//! # FRI parameters
//!
//! Both backends fix a concrete set of FRI parameters. These are chosen for
//! reasonable security and small proof size at the circuit sizes this crate
//! targets, but they are **not** tunable at runtime. Changing them produces
//! proofs that are incompatible with the verify functions in [`crate::api`].
//!
//! | Parameter | Standard | Hiding | Notes |
//! |---|---|---|---|
//! | `log_blowup` | 1 | 2 | Hiding needs higher blowup for randomizer columns |
//! | `num_queries` | 40 | 40 | |
//! | `query_proof_of_work_bits` | 8 | 8 | |
//! | `num_randomizer_cols` | -- | 4 | Extra columns for hiding |
//!
//! # Invariants
//!
//! - [`HidingBackend::config`] draws fresh OS entropy for every call.
//!   Two configs from `config()` produce unlinkable proofs.
//! - [`HidingBackend::verifier_config`] uses deterministic seeds. The
//!   verification path in `HidingFriPcs` never draws blinding randomness,
//!   so the seed value is irrelevant to correctness.
//! - [`HidingBackend::deterministic_config`] is for tests only. Proofs are
//!   reproducible and linkable.

use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, HidingFriPcs, TwoAdicFriPcs};
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_merkle_tree::{MerkleTreeHidingMmcs, MerkleTreeMmcs};
use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
use p3_uni_stark::StarkConfig;
use rand::SeedableRng;
use rand::rngs::{StdRng, SysRng};

// ---------------------------------------------------------------------------
// Shared FRI parameters
// ---------------------------------------------------------------------------

const NUM_QUERIES: usize = 40;
const QUERY_POW_BITS: usize = 8;
const LOG_BLOWUP_STANDARD: usize = 1;
const LOG_BLOWUP_HIDING: usize = 2;
const NUM_RANDOMIZER_COLS: usize = 4;

// ---------------------------------------------------------------------------
// Shared type aliases
// ---------------------------------------------------------------------------

type Val = BabyBear;
type Challenge = BinomialExtensionField<Val, 4>;
type ByteHash = Keccak256Hash;
type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
type FieldHash = SerializingHasher<U64Hash>;
type Compress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
type Dft = Radix2DitParallel<Val>;
type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;

// ---------------------------------------------------------------------------
// HidingRng
// ---------------------------------------------------------------------------

/// A CSPRNG suitable for hiding commitments.
///
/// Wraps `StdRng` (ChaCha12) seeded from OS entropy. Implements `Clone`
/// by drawing a fresh seed from the OS, so each clone gets independent
/// randomness -- the correct behavior for blinding leaves in separate
/// MMCS instances.
///
/// A deterministic variant is available via `from_test_seed` for
/// reproducible test snapshots; it is not suitable for production use.
#[derive(Debug)]
pub struct HidingRng {
    inner: StdRng,
    test_seed: Option<u64>,
}

impl HidingRng {
    pub fn from_os_entropy() -> Self {
        Self {
            inner: StdRng::try_from_rng(&mut SysRng).expect("OS entropy unavailable"),
            test_seed: None,
        }
    }

    fn from_test_seed(seed: u64) -> Self {
        Self {
            inner: StdRng::seed_from_u64(seed),
            test_seed: Some(seed),
        }
    }
}

impl Clone for HidingRng {
    fn clone(&self) -> Self {
        match self.test_seed {
            Some(seed) => Self::from_test_seed(seed),
            None => Self::from_os_entropy(),
        }
    }
}

impl rand_core::TryRng for HidingRng {
    type Error = core::convert::Infallible;

    #[inline]
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.inner.try_next_u32()
    }

    #[inline]
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.inner.try_next_u64()
    }

    #[inline]
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.inner.try_fill_bytes(dst)
    }
}

impl rand_core::TryCryptoRng for HidingRng {}

// ---------------------------------------------------------------------------
// Non-hiding (standard) backend
// ---------------------------------------------------------------------------

type StdValMmcs = MerkleTreeMmcs<
    [Val; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    FieldHash,
    Compress,
    2, 4,
>;
type StdChallengeMmcs = ExtensionMmcs<Val, Challenge, StdValMmcs>;
type StdPcs = TwoAdicFriPcs<Val, Dft, StdValMmcs, StdChallengeMmcs>;

pub type StandardConfig = StarkConfig<StdPcs, Challenge, Challenger>;

pub struct StandardBackend;

impl StandardBackend {
    pub fn config() -> StandardConfig {
        let byte_hash = ByteHash {};
        let u64_hash = U64Hash::new(KeccakF {});
        let field_hash = FieldHash::new(u64_hash);
        let compress = Compress::new(u64_hash);

        let val_mmcs = StdValMmcs::new(field_hash, compress, 0);
        let challenge_mmcs = StdChallengeMmcs::new(val_mmcs.clone());

        let fri_params = FriParameters {
            log_blowup: LOG_BLOWUP_STANDARD,
            log_final_poly_len: 0,
            max_log_arity: 2,
            num_queries: NUM_QUERIES,
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: QUERY_POW_BITS,
            mmcs: challenge_mmcs,
        };

        let dft = Dft::default();
        let pcs = StdPcs::new(dft, val_mmcs, fri_params);
        let challenger = Challenger::from_hasher(vec![], byte_hash);

        StandardConfig::new(pcs, challenger)
    }
}

// ---------------------------------------------------------------------------
// Hiding (ZK) backend
// ---------------------------------------------------------------------------

type ZkValMmcs = MerkleTreeHidingMmcs<
    [Val; p3_keccak::VECTOR_LEN],
    [u64; p3_keccak::VECTOR_LEN],
    FieldHash,
    Compress,
    HidingRng,
    2, 4, 4,
>;
type ZkChallengeMmcs = ExtensionMmcs<Val, Challenge, ZkValMmcs>;
type ZkPcs = HidingFriPcs<Val, Dft, ZkValMmcs, ZkChallengeMmcs, HidingRng>;

pub type HidingConfig = StarkConfig<ZkPcs, Challenge, Challenger>;

pub struct HidingBackend;

impl HidingBackend {
    /// Production hiding config with OS-entropy-seeded CSPRNG blinding.
    ///
    /// Each call produces a fresh config with independent randomness.
    /// Two proofs from different `config()` calls are unlinkable.
    pub fn config() -> HidingConfig {
        Self::build(HidingRng::from_os_entropy(), HidingRng::from_os_entropy())
    }

    /// Config for verification only.
    ///
    /// Uses deterministic seeds because the `HidingFriPcs` verification path
    /// never draws blinding randomness. The seed value is irrelevant to
    /// correctness -- it exists only to satisfy the type-level RNG requirement.
    pub fn verifier_config() -> HidingConfig {
        Self::build(HidingRng::from_test_seed(0), HidingRng::from_test_seed(0))
    }

    /// Deterministic hiding config for reproducible test snapshots.
    ///
    /// Proofs produced with this config are linkable and predictable.
    /// **Not suitable for production use.**
    pub fn deterministic_config(seed: u64) -> HidingConfig {
        Self::build(HidingRng::from_test_seed(seed), HidingRng::from_test_seed(seed + 1))
    }

    fn build(mmcs_rng: HidingRng, pcs_rng: HidingRng) -> HidingConfig {
        let byte_hash = ByteHash {};
        let u64_hash = U64Hash::new(KeccakF {});
        let field_hash = FieldHash::new(u64_hash);
        let compress = Compress::new(u64_hash);

        let val_mmcs = ZkValMmcs::new(field_hash, compress, 0, mmcs_rng);
        let challenge_mmcs = ZkChallengeMmcs::new(val_mmcs.clone());

        let fri_params = FriParameters {
            log_blowup: LOG_BLOWUP_HIDING,
            log_final_poly_len: 0,
            max_log_arity: 2,
            num_queries: NUM_QUERIES,
            commit_proof_of_work_bits: 0,
            query_proof_of_work_bits: QUERY_POW_BITS,
            mmcs: challenge_mmcs,
        };

        let dft = Dft::default();
        let pcs = ZkPcs::new(dft, val_mmcs, fri_params, NUM_RANDOMIZER_COLS, pcs_rng);
        let challenger = Challenger::from_hasher(vec![], byte_hash);

        HidingConfig::new(pcs, challenger)
    }
}
