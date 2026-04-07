use std::time::Instant;

use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_zk_proofs::{WIDTH, prove_preimage_hiding, prove_preimage_standard, verify_preimage};

fn main() {
    let preimage: [BabyBear; WIDTH] = core::array::from_fn(|i| BabyBear::from_u64((i + 1) as u64));
    let seed = 42; // selects Poseidon2 round constants

    println!("=== Poseidon2 Preimage ZK Proof ===\n");
    println!("Preimage (private): {:?}", &preimage[..4]);
    println!("  ... ({} elements total)\n", preimage.len());

    // Standard (non-ZK) proof
    {
        let t = Instant::now();
        let proof = prove_preimage_standard(preimage, seed);
        let prove_us = t.elapsed().as_micros();

        println!("Hash output (public): {:?}", &proof.public_values()[..4]);
        println!("  ... ({} elements total)\n", proof.public_values().len());

        let t = Instant::now();
        verify_preimage(&proof).expect("standard proof verification failed");
        let verify_us = t.elapsed().as_micros();

        println!(
            "[Standard] Prove: {:.2}ms, Verify: {:.2}ms, Proof: {} bytes",
            prove_us as f64 / 1000.0,
            verify_us as f64 / 1000.0,
            proof.proof_size_bytes(),
        );
    }

    // Hiding (ZK) proof
    {
        let t = Instant::now();
        let proof = prove_preimage_hiding(preimage, seed);
        let prove_us = t.elapsed().as_micros();

        let t = Instant::now();
        verify_preimage(&proof).expect("hiding proof verification failed");
        let verify_us = t.elapsed().as_micros();

        println!(
            "[Hiding]   Prove: {:.2}ms, Verify: {:.2}ms, Proof: {} bytes",
            prove_us as f64 / 1000.0,
            verify_us as f64 / 1000.0,
            proof.proof_size_bytes(),
        );
    }

    println!("\nThe hiding proof hides the preimage from the verifier.");
    println!("The verifier only sees the hash output and the proof.");
}
