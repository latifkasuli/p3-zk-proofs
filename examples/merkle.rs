use std::time::Instant;

use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_zk_proofs::{
    prove_merkle_inclusion_standard, prove_merkle_inclusion_hiding,
    verify_merkle_inclusion, DIGEST_WIDTH,
};

fn main() {
    let depth = 8;
    let leaf_index: u64 = 42;
    let seed = 7; // selects Poseidon2 round constants

    let leaf: [BabyBear; DIGEST_WIDTH] =
        core::array::from_fn(|i| BabyBear::from_u64((i + 1) as u64));

    let siblings: Vec<[BabyBear; DIGEST_WIDTH]> = (0..depth)
        .map(|level| {
            core::array::from_fn(|i| BabyBear::from_u64((level * 100 + i + 50) as u64))
        })
        .collect();

    println!("=== Merkle Inclusion ZK Proof ===\n");
    println!("Tree depth: {}", depth);
    println!("Leaf index (private): {}", leaf_index);
    println!("Leaf value (private): {:?}", &leaf[..4]);
    println!("  ... ({} elements total)\n", leaf.len());

    // Standard
    {
        let t = Instant::now();
        let proof = prove_merkle_inclusion_standard(leaf, &siblings, leaf_index, depth, seed);
        let prove_us = t.elapsed().as_micros();

        println!("Root (public): {:?}", &proof.public_values()[..4]);
        println!("  ... ({} elements total)\n", proof.public_values().len());

        let t = Instant::now();
        verify_merkle_inclusion(&proof).expect("standard Merkle proof failed");
        let verify_us = t.elapsed().as_micros();

        println!(
            "[Standard] Prove: {:.2}ms, Verify: {:.2}ms, Proof: {} bytes",
            prove_us as f64 / 1000.0,
            verify_us as f64 / 1000.0,
            proof.proof_size_bytes(),
        );
    }

    // Hiding
    {
        let t = Instant::now();
        let proof = prove_merkle_inclusion_hiding(leaf, &siblings, leaf_index, depth, seed);
        let prove_us = t.elapsed().as_micros();

        let t = Instant::now();
        verify_merkle_inclusion(&proof).expect("hiding Merkle proof failed");
        let verify_us = t.elapsed().as_micros();

        println!(
            "[Hiding]   Prove: {:.2}ms, Verify: {:.2}ms, Proof: {} bytes",
            prove_us as f64 / 1000.0,
            verify_us as f64 / 1000.0,
            proof.proof_size_bytes(),
        );
    }

    println!("\nThe hiding proof conceals the leaf, its position, and");
    println!("all sibling hashes. Only the root is public.");
}
