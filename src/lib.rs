//! Reference ZK applications on Plonky3.
//!
//! This crate provides two privacy-preserving circuits -- hash preimage and
//! Merkle inclusion -- with a one-call prove/verify API on top of Plonky3's
//! `uni-stark` prover and `HidingFriPcs` commitment scheme.
//!
//! # Stability
//!
//! This is a **reference implementation**. The public API surface is
//! intentionally small and may change between minor versions. In particular:
//!
//! - Proof bundle types ([`PreimageProof`], [`MerkleInclusionProof`]) are
//!   in-process wrappers, not a stable wire format.
//! - [`FORMAT_VERSION`] tracks layout-breaking changes but does **not** imply
//!   cross-version compatibility.
//! - Backend configs ([`backend::StandardBackend`], [`backend::HidingBackend`])
//!   fix specific FRI parameters. Changing them produces incompatible proofs.
//!
//! # Non-goals
//!
//! - General-purpose proof framework or DSL.
//! - Persistent proof storage or cross-language interop.
//! - Performance-optimized production prover (no GPU, no parallelism by default).
//! - Formal security analysis -- the hiding properties inherit from Plonky3's
//!   `HidingFriPcs` and are only as strong as that implementation.

pub mod api;
pub mod air;
pub mod backend;

pub use api::{
    BackendKind, ProofMetadata, VerifyError, FORMAT_VERSION,
    PreimageProof, MerkleInclusionProof,
    prove_preimage_standard, prove_preimage_hiding, verify_preimage,
    prove_merkle_inclusion_standard, prove_merkle_inclusion_hiding, verify_merkle_inclusion,
};
pub use air::{FieldElement, WIDTH, DIGEST_WIDTH};
