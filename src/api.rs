//! One-call prove/verify API for the reference ZK applications.
//!
//! This module is the intended public surface of the crate. It wraps the
//! internal AIR definitions and backend configurations behind a small set
//! of functions that accept application-level inputs and return self-contained
//! proof bundles.
//!
//! # Proof bundles
//!
//! [`PreimageProof`] and [`MerkleInclusionProof`] are **in-process wrappers**.
//! They carry the raw `p3-uni-stark` proof together with the metadata needed
//! to reconstruct the AIR and config for verification, so the caller never
//! touches backend internals directly.
//!
//! Proof bundles are **not** a stable serialization format. The inner proof
//! can be round-tripped through `postcard` within the same crate version
//! (and [`proof_size_bytes`](PreimageProof::proof_size_bytes) uses this for
//! measurement), but the byte layout is not versioned for cross-version
//! compatibility. If you need to persist or transport proofs, serialize the
//! inner proof yourself and reconstruct the verification context from shared
//! prover/verifier parameters (`params_seed`, `depth`, backend choice).
//!
//! # Format version
//!
//! [`FORMAT_VERSION`] is bumped whenever the proof layout, backend config
//! parameters, or public-value encoding changes in a way that would cause a
//! proof produced by one version to fail verification under another. It is
//! an internal consistency marker, not a wire-protocol version.
//!
//! # Error model
//!
//! [`VerifyError`] is `#[non_exhaustive]` so that future releases can add
//! failure variants without a semver break. Callers should match on known
//! variants and have a catch-all arm.

use alloc::vec::Vec;

extern crate alloc;

use p3_uni_stark::{prove, verify};

use crate::air::preimage::PreimageAir;
use crate::air::merkle::MerkleInclusionAir;
use crate::air::{FieldElement, DIGEST_WIDTH, WIDTH};
use crate::backend::{HidingBackend, HidingConfig, StandardBackend, StandardConfig};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Proof format version.
///
/// Bumped when backend config parameters, public-value layout, or inner proof
/// structure changes in a way that breaks verification compatibility. Two
/// proof bundles with different format versions are not interchangeable.
///
/// This is **not** a wire-protocol version. It exists so that future test
/// fixtures or snapshot comparisons can detect stale proof data early.
pub const FORMAT_VERSION: u8 = 1;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Which proving backend produced a proof.
///
/// Marked `#[non_exhaustive]` so that adding a new backend variant (e.g. a
/// future GPU-accelerated mode) is not a semver-breaking change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum BackendKind {
    /// Non-hiding FRI PCS. Fast, but the trace is not blinded.
    Standard,
    /// Hiding FRI PCS with CSPRNG-salted Merkle leaves and randomizer
    /// polynomials. The prover's witness is hidden from the verifier.
    Hiding,
}

/// Metadata that travels with every proof bundle.
///
/// All fields are public for inspection, but callers should not construct
/// this type directly -- it is populated by the prove functions.
#[derive(Clone, Debug)]
pub struct ProofMetadata {
    pub backend: BackendKind,
    /// Circuit identifier, e.g. `"preimage"` or `"merkle_inclusion"`.
    pub circuit: &'static str,
    /// Seed used to derive Poseidon2 round constants. Part of the public
    /// statement: prover and verifier must agree on this value.
    pub params_seed: u64,
    /// Public values committed by the prover (hash output or Merkle root).
    pub public_values: Vec<FieldElement>,
}

/// Error returned when proof verification fails.
///
/// Marked `#[non_exhaustive]` so that future releases can add structured
/// variants (e.g. `FormatVersionMismatch`, `DeserializationFailed`) without
/// a semver break. Match on known variants and include a catch-all arm.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum VerifyError {
    /// The STARK constraint system rejected the proof.
    ConstraintFailure(String),
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifyError::ConstraintFailure(msg) => write!(f, "constraint failure: {msg}"),
        }
    }
}

impl std::error::Error for VerifyError {}

// ---------------------------------------------------------------------------
// Preimage proof
// ---------------------------------------------------------------------------

/// Self-contained Poseidon2 preimage proof.
///
/// Carries the inner STARK proof, public values (the hash output), and
/// enough metadata to reconstruct the AIR and config for verification.
///
/// This type is intentionally opaque: the inner proof is not directly
/// accessible. Use [`verify_preimage`] to check it, or
/// [`proof_size_bytes`](Self::proof_size_bytes) to measure it.
#[must_use]
pub struct PreimageProof {
    inner: PreimageProofInner,
    meta: ProofMetadata,
}

enum PreimageProofInner {
    Standard(p3_uni_stark::Proof<StandardConfig>),
    Hiding(p3_uni_stark::Proof<HidingConfig>),
}

impl PreimageProof {
    pub fn metadata(&self) -> &ProofMetadata {
        &self.meta
    }

    pub fn public_values(&self) -> &[FieldElement] {
        &self.meta.public_values
    }

    pub fn backend(&self) -> BackendKind {
        self.meta.backend
    }

    /// Size of the inner STARK proof in bytes (postcard encoding).
    ///
    /// This measures only the `p3-uni-stark::Proof`, not the metadata.
    /// The value is computed on every call (no caching).
    pub fn proof_size_bytes(&self) -> usize {
        match &self.inner {
            PreimageProofInner::Standard(p) => postcard::to_allocvec(p).map(|v| v.len()).unwrap_or(0),
            PreimageProofInner::Hiding(p) => postcard::to_allocvec(p).map(|v| v.len()).unwrap_or(0),
        }
    }
}

/// Prove knowledge of `preimage` such that `Poseidon2(preimage) = hash_output`,
/// without revealing the preimage. Uses the non-hiding backend.
pub fn prove_preimage_standard(
    preimage: [FieldElement; WIDTH],
    params_seed: u64,
) -> PreimageProof {
    let air = PreimageAir::new(params_seed);
    let config = StandardBackend::config();
    let witness = air.generate_witness(preimage, 1);
    let proof = prove(&config, &air, witness.trace, &witness.public_values);
    PreimageProof {
        inner: PreimageProofInner::Standard(proof),
        meta: ProofMetadata {
            backend: BackendKind::Standard,
            circuit: "preimage",
            params_seed,
            public_values: witness.public_values,
        },
    }
}

/// Prove knowledge of `preimage` such that `Poseidon2(preimage) = hash_output`,
/// without revealing the preimage. Uses the hiding (ZK) backend with
/// CSPRNG-blinded commitments.
pub fn prove_preimage_hiding(
    preimage: [FieldElement; WIDTH],
    params_seed: u64,
) -> PreimageProof {
    let air = PreimageAir::new(params_seed);
    let config = HidingBackend::config();
    let witness = air.generate_witness(preimage, 2);
    let proof = prove(&config, &air, witness.trace, &witness.public_values);
    PreimageProof {
        inner: PreimageProofInner::Hiding(proof),
        meta: ProofMetadata {
            backend: BackendKind::Hiding,
            circuit: "preimage",
            params_seed,
            public_values: witness.public_values,
        },
    }
}

/// Verify a preimage proof against its embedded public values.
///
/// Reconstructs the AIR and config from the proof's metadata, so the
/// caller only needs the proof bundle itself.
pub fn verify_preimage(proof: &PreimageProof) -> Result<(), VerifyError> {
    let air = PreimageAir::new(proof.meta.params_seed);
    match &proof.inner {
        PreimageProofInner::Standard(p) => {
            let config = StandardBackend::config();
            verify(&config, &air, p, &proof.meta.public_values)
                .map_err(|e| VerifyError::ConstraintFailure(alloc::format!("{e}")))
        }
        PreimageProofInner::Hiding(p) => {
            let config = HidingBackend::verifier_config();
            verify(&config, &air, p, &proof.meta.public_values)
                .map_err(|e| VerifyError::ConstraintFailure(alloc::format!("{e}")))
        }
    }
}

// ---------------------------------------------------------------------------
// Merkle inclusion proof
// ---------------------------------------------------------------------------

/// Self-contained Merkle tree inclusion proof.
///
/// Carries the inner STARK proof, public values (the root digest), and
/// enough metadata to reconstruct the AIR and config for verification.
///
/// See [`PreimageProof`] for the same design rationale regarding opacity
/// and serialization.
#[must_use]
pub struct MerkleInclusionProof {
    inner: MerkleProofInner,
    meta: ProofMetadata,
    depth: usize,
}

enum MerkleProofInner {
    Standard(p3_uni_stark::Proof<StandardConfig>),
    Hiding(p3_uni_stark::Proof<HidingConfig>),
}

impl MerkleInclusionProof {
    pub fn metadata(&self) -> &ProofMetadata {
        &self.meta
    }

    pub fn public_values(&self) -> &[FieldElement] {
        &self.meta.public_values
    }

    pub fn backend(&self) -> BackendKind {
        self.meta.backend
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    /// Size of the inner STARK proof in bytes (postcard encoding).
    ///
    /// This measures only the `p3-uni-stark::Proof`, not the metadata.
    /// The value is computed on every call (no caching).
    pub fn proof_size_bytes(&self) -> usize {
        match &self.inner {
            MerkleProofInner::Standard(p) => postcard::to_allocvec(p).map(|v| v.len()).unwrap_or(0),
            MerkleProofInner::Hiding(p) => postcard::to_allocvec(p).map(|v| v.len()).unwrap_or(0),
        }
    }
}

/// Prove that `leaf` is at `leaf_index` in a Merkle tree with the given
/// `siblings`, without revealing the leaf, index, or path.
/// Uses the non-hiding backend.
pub fn prove_merkle_inclusion_standard(
    leaf: [FieldElement; DIGEST_WIDTH],
    siblings: &[[FieldElement; DIGEST_WIDTH]],
    leaf_index: u64,
    depth: usize,
    params_seed: u64,
) -> MerkleInclusionProof {
    let air = MerkleInclusionAir::new(depth, params_seed);
    let config = StandardBackend::config();
    let witness = air.generate_witness(leaf, siblings, leaf_index, 1);
    let proof = prove(&config, &air, witness.trace, &witness.public_values);
    MerkleInclusionProof {
        inner: MerkleProofInner::Standard(proof),
        meta: ProofMetadata {
            backend: BackendKind::Standard,
            circuit: "merkle_inclusion",
            params_seed,
            public_values: witness.public_values,
        },
        depth,
    }
}

/// Prove that `leaf` is at `leaf_index` in a Merkle tree with the given
/// `siblings`, without revealing the leaf, index, or path.
/// Uses the hiding (ZK) backend with CSPRNG-blinded commitments.
pub fn prove_merkle_inclusion_hiding(
    leaf: [FieldElement; DIGEST_WIDTH],
    siblings: &[[FieldElement; DIGEST_WIDTH]],
    leaf_index: u64,
    depth: usize,
    params_seed: u64,
) -> MerkleInclusionProof {
    let air = MerkleInclusionAir::new(depth, params_seed);
    let config = HidingBackend::config();
    let witness = air.generate_witness(leaf, siblings, leaf_index, 2);
    let proof = prove(&config, &air, witness.trace, &witness.public_values);
    MerkleInclusionProof {
        inner: MerkleProofInner::Hiding(proof),
        meta: ProofMetadata {
            backend: BackendKind::Hiding,
            circuit: "merkle_inclusion",
            params_seed,
            public_values: witness.public_values,
        },
        depth,
    }
}

/// Verify a Merkle inclusion proof against its embedded root digest.
///
/// Reconstructs the AIR and config from the proof's metadata, so the
/// caller only needs the proof bundle itself.
pub fn verify_merkle_inclusion(proof: &MerkleInclusionProof) -> Result<(), VerifyError> {
    let air = MerkleInclusionAir::new(proof.depth, proof.meta.params_seed);
    match &proof.inner {
        MerkleProofInner::Standard(p) => {
            let config = StandardBackend::config();
            verify(&config, &air, p, &proof.meta.public_values)
                .map_err(|e| VerifyError::ConstraintFailure(alloc::format!("{e}")))
        }
        MerkleProofInner::Hiding(p) => {
            let config = HidingBackend::verifier_config();
            verify(&config, &air, p, &proof.meta.public_values)
                .map_err(|e| VerifyError::ConstraintFailure(alloc::format!("{e}")))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use p3_field::PrimeCharacteristicRing;

    fn test_preimage() -> [FieldElement; WIDTH] {
        core::array::from_fn(|i| FieldElement::from_u64((i + 1) as u64))
    }

    // -- Preimage roundtrip + metadata -----------------------------------

    #[test]
    fn preimage_standard_roundtrip() {
        let proof = prove_preimage_standard(test_preimage(), 42);
        assert_eq!(proof.backend(), BackendKind::Standard);
        assert_eq!(proof.metadata().circuit, "preimage");
        assert_eq!(proof.public_values().len(), WIDTH);
        assert!(proof.proof_size_bytes() > 0);
        verify_preimage(&proof).expect("valid standard preimage proof");
    }

    #[test]
    fn preimage_hiding_roundtrip() {
        let proof = prove_preimage_hiding(test_preimage(), 42);
        assert_eq!(proof.backend(), BackendKind::Hiding);
        assert!(proof.proof_size_bytes() > 0);
        verify_preimage(&proof).expect("valid hiding preimage proof");
    }

    #[test]
    fn preimage_tampered_public_values_rejected() {
        let mut proof = prove_preimage_standard(test_preimage(), 42);
        proof.meta.public_values[0] += FieldElement::ONE;
        assert!(verify_preimage(&proof).is_err());
    }

    // -- Preimage serialization roundtrip --------------------------------

    #[test]
    fn preimage_standard_serde_roundtrip() {
        let proof = prove_preimage_standard(test_preimage(), 42);
        let bytes = match &proof.inner {
            PreimageProofInner::Standard(p) => postcard::to_allocvec(p).unwrap(),
            _ => unreachable!(),
        };
        let deserialized: p3_uni_stark::Proof<StandardConfig> =
            postcard::from_bytes(&bytes).unwrap();
        let air = PreimageAir::new(42);
        let config = StandardBackend::config();
        verify(&config, &air, &deserialized, &proof.meta.public_values)
            .expect("deserialized proof should verify");
    }

    #[test]
    fn preimage_hiding_serde_roundtrip() {
        let proof = prove_preimage_hiding(test_preimage(), 42);
        let bytes = match &proof.inner {
            PreimageProofInner::Hiding(p) => postcard::to_allocvec(p).unwrap(),
            _ => unreachable!(),
        };
        let deserialized: p3_uni_stark::Proof<HidingConfig> =
            postcard::from_bytes(&bytes).unwrap();
        let air = PreimageAir::new(42);
        let config = HidingBackend::verifier_config();
        verify(&config, &air, &deserialized, &proof.meta.public_values)
            .expect("deserialized hiding proof should verify");
    }

    #[test]
    fn preimage_tampered_bytes_fail() {
        let proof = prove_preimage_standard(test_preimage(), 42);
        let mut bytes = match &proof.inner {
            PreimageProofInner::Standard(p) => postcard::to_allocvec(p).unwrap(),
            _ => unreachable!(),
        };
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0xff;
        let result: Result<p3_uni_stark::Proof<StandardConfig>, _> =
            postcard::from_bytes(&bytes);
        if let Ok(tampered) = result {
            let air = PreimageAir::new(42);
            let config = StandardBackend::config();
            assert!(
                verify(&config, &air, &tampered, &proof.meta.public_values).is_err(),
                "tampered proof bytes should fail verification"
            );
        }
    }

    // -- Merkle roundtrip + metadata -------------------------------------

    #[test]
    fn merkle_standard_roundtrip() {
        let (leaf, siblings, leaf_index, depth, seed) = merkle_fixture(4);
        let proof = prove_merkle_inclusion_standard(leaf, &siblings, leaf_index, depth, seed);
        assert_eq!(proof.backend(), BackendKind::Standard);
        assert_eq!(proof.depth(), depth);
        assert_eq!(proof.metadata().circuit, "merkle_inclusion");
        assert_eq!(proof.public_values().len(), DIGEST_WIDTH);
        assert!(proof.proof_size_bytes() > 0);
        verify_merkle_inclusion(&proof).expect("valid standard merkle proof");
    }

    #[test]
    fn merkle_hiding_roundtrip() {
        let (leaf, siblings, leaf_index, depth, seed) = merkle_fixture(4);
        let proof = prove_merkle_inclusion_hiding(leaf, &siblings, leaf_index, depth, seed);
        assert_eq!(proof.backend(), BackendKind::Hiding);
        assert!(proof.proof_size_bytes() > 0);
        verify_merkle_inclusion(&proof).expect("valid hiding merkle proof");
    }

    #[test]
    fn merkle_tampered_root_rejected() {
        let (leaf, siblings, leaf_index, depth, seed) = merkle_fixture(4);
        let mut proof = prove_merkle_inclusion_standard(leaf, &siblings, leaf_index, depth, seed);
        proof.meta.public_values[0] += FieldElement::ONE;
        assert!(verify_merkle_inclusion(&proof).is_err());
    }

    // -- Merkle depth coverage -------------------------------------------

    #[test]
    fn merkle_depth_1() {
        let (leaf, siblings, leaf_index, depth, seed) = merkle_fixture(1);
        let proof = prove_merkle_inclusion_standard(leaf, &siblings, leaf_index, depth, seed);
        verify_merkle_inclusion(&proof).expect("depth-1 merkle proof");
    }

    #[test]
    fn merkle_depth_8() {
        let (leaf, siblings, leaf_index, depth, seed) = merkle_fixture(8);
        let proof = prove_merkle_inclusion_standard(leaf, &siblings, leaf_index, depth, seed);
        verify_merkle_inclusion(&proof).expect("depth-8 merkle proof");
    }

    // -- Merkle serialization roundtrip ----------------------------------

    #[test]
    fn merkle_standard_serde_roundtrip() {
        let (leaf, siblings, leaf_index, depth, seed) = merkle_fixture(4);
        let proof = prove_merkle_inclusion_standard(leaf, &siblings, leaf_index, depth, seed);
        let bytes = match &proof.inner {
            MerkleProofInner::Standard(p) => postcard::to_allocvec(p).unwrap(),
            _ => unreachable!(),
        };
        let deserialized: p3_uni_stark::Proof<StandardConfig> =
            postcard::from_bytes(&bytes).unwrap();
        let air = MerkleInclusionAir::new(depth, seed);
        let config = StandardBackend::config();
        verify(&config, &air, &deserialized, &proof.meta.public_values)
            .expect("deserialized merkle proof should verify");
    }

    #[test]
    fn merkle_hiding_serde_roundtrip() {
        let (leaf, siblings, leaf_index, depth, seed) = merkle_fixture(4);
        let proof = prove_merkle_inclusion_hiding(leaf, &siblings, leaf_index, depth, seed);
        let bytes = match &proof.inner {
            MerkleProofInner::Hiding(p) => postcard::to_allocvec(p).unwrap(),
            _ => unreachable!(),
        };
        let deserialized: p3_uni_stark::Proof<HidingConfig> =
            postcard::from_bytes(&bytes).unwrap();
        let air = MerkleInclusionAir::new(depth, seed);
        let config = HidingBackend::verifier_config();
        verify(&config, &air, &deserialized, &proof.meta.public_values)
            .expect("deserialized hiding merkle proof should verify");
    }

    // -- RNG mode semantics ----------------------------------------------

    #[test]
    fn deterministic_config_produces_equal_proofs() {
        use crate::air::preimage::PreimageAir;
        let air = PreimageAir::new(42);
        let preimage = test_preimage();

        let config_a = HidingBackend::deterministic_config(99);
        let w_a = air.generate_witness(preimage, 2);
        let proof_a = p3_uni_stark::prove(&config_a, &air, w_a.trace, &w_a.public_values);
        let bytes_a = postcard::to_allocvec(&proof_a).unwrap();

        let config_b = HidingBackend::deterministic_config(99);
        let w_b = air.generate_witness(preimage, 2);
        let proof_b = p3_uni_stark::prove(&config_b, &air, w_b.trace, &w_b.public_values);
        let bytes_b = postcard::to_allocvec(&proof_b).unwrap();

        assert_eq!(bytes_a, bytes_b, "same seed should produce identical proof bytes");
    }

    #[test]
    fn production_config_produces_different_proofs() {
        use crate::air::preimage::PreimageAir;
        let air = PreimageAir::new(42);
        let preimage = test_preimage();

        let config_a = HidingBackend::config();
        let w_a = air.generate_witness(preimage, 2);
        let proof_a = p3_uni_stark::prove(&config_a, &air, w_a.trace, &w_a.public_values);
        let bytes_a = postcard::to_allocvec(&proof_a).unwrap();

        let config_b = HidingBackend::config();
        let w_b = air.generate_witness(preimage, 2);
        let proof_b = p3_uni_stark::prove(&config_b, &air, w_b.trace, &w_b.public_values);
        let bytes_b = postcard::to_allocvec(&proof_b).unwrap();

        assert_ne!(bytes_a, bytes_b, "OS-seeded configs should produce different proof bytes");
    }

    // -- Test helpers ----------------------------------------------------

    fn merkle_fixture(depth: usize) -> (
        [FieldElement; DIGEST_WIDTH],
        Vec<[FieldElement; DIGEST_WIDTH]>,
        u64,
        usize,
        u64,
    ) {
        use crate::air::poseidon2_compress;
        use p3_baby_bear::GenericPoseidon2LinearLayersBabyBear;
        use crate::air::Poseidon2Params;
        use rand::SeedableRng;
        use rand::rngs::SmallRng;

        let seed = 42u64;
        let mut rng = SmallRng::seed_from_u64(seed);
        let params = Poseidon2Params::from_rng(&mut rng);

        let leaf: [FieldElement; DIGEST_WIDTH] =
            core::array::from_fn(|i| FieldElement::from_u64(i as u64 + 1));
        let leaf_index: u64 = 3;

        let mut siblings = Vec::with_capacity(depth);
        let mut current = leaf;
        for level in 0..depth {
            let sibling: [FieldElement; DIGEST_WIDTH] =
                core::array::from_fn(|i| FieldElement::from_u64((level * 100 + i + 50) as u64));
            let is_right = ((leaf_index >> level) & 1) == 1;
            let (left, right) = if is_right {
                (&sibling, &current)
            } else {
                (&current, &sibling)
            };
            current = poseidon2_compress::<FieldElement, GenericPoseidon2LinearLayersBabyBear>(
                left, right, &params,
            );
            siblings.push(sibling);
        }

        (leaf, siblings, leaf_index, depth, seed)
    }
}
