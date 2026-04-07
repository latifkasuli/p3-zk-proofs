# p3-zk-proofs

Reference ZK applications on [Plonky3](https://github.com/Plonky3/Plonky3).

## Why this repo exists

Plonky3 ships `HidingFriPcs` and a low-level benchmark example, but no
application-level code that shows how to build a privacy-preserving proof
end to end. This repo fills that gap with two concrete circuits and a
one-call prove/verify API:

- **Hash preimage** -- prove knowledge of `x` such that `Poseidon2(x) = y`, without revealing `x`.
- **Merkle inclusion** -- prove a leaf belongs to a Merkle tree, without revealing the leaf, its index, or the authentication path.

Both circuits run on BabyBear / Keccak / FRI with two backend modes:

| Backend | Blinding | Use case |
|---|---|---|
| `Standard` | None | Fast proofs where privacy is not required |
| `Hiding` | CSPRNG-salted Merkle leaves + randomizer polynomials | ZK proofs that hide the witness from the verifier |

## Quick start

```rust
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_zk_proofs::{prove_preimage_hiding, verify_preimage, WIDTH};

let preimage: [BabyBear; WIDTH] =
    core::array::from_fn(|i| BabyBear::from_u64((i + 1) as u64));

// params_seed selects the Poseidon2 round constants.
// Both prover and verifier must agree on the same seed.
let proof = prove_preimage_hiding(preimage, /* params_seed */ 42);

// The verifier only sees the hash output, never the preimage.
assert!(verify_preimage(&proof).is_ok());
println!("Hash output: {:?}", proof.public_values());
println!("Proof size: {} bytes", proof.proof_size_bytes());
```

Merkle inclusion:

```rust
use p3_zk_proofs::{
    prove_merkle_inclusion_hiding, verify_merkle_inclusion,
};

let proof = prove_merkle_inclusion_hiding(
    leaf,           // private
    &siblings,      // private
    leaf_index,     // private
    depth,
    params_seed,    // shared between prover and verifier
);

// The verifier only sees the Merkle root.
assert!(verify_merkle_inclusion(&proof).is_ok());
println!("Root: {:?}", proof.public_values());
println!("Proof size: {} bytes", proof.proof_size_bytes());
```

## API

All prove/verify functions live at crate root:

| Function | Returns |
|---|---|
| `prove_preimage_standard(preimage, seed)` | `PreimageProof` |
| `prove_preimage_hiding(preimage, seed)` | `PreimageProof` |
| `verify_preimage(&proof)` | `Result<(), VerifyError>` |
| `prove_merkle_inclusion_standard(leaf, siblings, index, depth, seed)` | `MerkleInclusionProof` |
| `prove_merkle_inclusion_hiding(leaf, siblings, index, depth, seed)` | `MerkleInclusionProof` |
| `verify_merkle_inclusion(&proof)` | `Result<(), VerifyError>` |

Each proof bundle carries its own metadata (`BackendKind`, public values,
circuit name, parameter seed) so verification requires only the proof itself.

Proof sizes are available via `proof.proof_size_bytes()` (postcard encoding).

### `params_seed`

The `params_seed` argument deterministically derives the Poseidon2 round
constants used by the circuit. It is part of the public statement: the
prover and verifier must use the same seed, and changing it changes the
hash function. This is standard practice in Plonky3.

## Performance

Source: `cargo bench` (Criterion `core/*` benchmarks), single-threaded.
Proof sizes via `postcard::to_allocvec` on the inner STARK proof.

Machine: Apple M3 (aarch64), Rust 1.94.0, Plonky3 0.5.2.

| Circuit | Backend | Prove | Verify | Proof size |
|---|---|---|---|---|
| Preimage (width 16) | Standard | ~330 us | ~580 us | 80 KiB |
| Preimage (width 16) | Hiding | ~430 us | ~750 us | 117 KiB |
| Merkle (depth 8) | Standard | ~2.0 ms | ~4.2 ms | 555 KiB |
| Merkle (depth 8) | Hiding | ~2.3 ms | ~4.3 ms | 595 KiB |

The `core/*` benchmarks pre-build the AIR, config, and witness to isolate
proving and verification cost. The `api/*` benchmarks measure the full
one-call API including setup. A Merkle depth sweep
(`core/merkle_depth/standard/prove`) tests depths 1, 4, 8, and 16:

| Depth | Prove |
|---|---|
| 1 | ~380 us |
| 4 | ~1.0 ms |
| 8 | ~2.0 ms |
| 16 | ~4.1 ms |

Reproduce on your machine:

```bash
cargo bench
cargo run --release --example preimage
cargo run --release --example merkle
```

## Project layout

```
src/
  api.rs          Top-level prove/verify functions and proof bundle types
  air/
    mod.rs        Poseidon2 primitives, constraint gadget, constants
    preimage.rs   Hash preimage AIR circuit
    merkle.rs     Merkle inclusion AIR circuit (wide-trace layout)
  backend.rs      Standard and Hiding backend configs, HidingRng (ChaCha12 CSPRNG)
  lib.rs          Public API re-exports
examples/
  preimage.rs     CLI demo for preimage proofs (with proof sizes)
  merkle.rs       CLI demo for Merkle inclusion proofs (with proof sizes)
benches/
  zk_overhead.rs  Criterion benchmarks: api/* (end-to-end) and core/* (prove-only)
```

## Security notes

- The hiding backend uses `StdRng` (ChaCha12) seeded from OS entropy via `SysRng`.
  Each MMCS and PCS instance gets independent randomness.
- Verification uses `HidingBackend::verifier_config()` with deterministic seeds,
  since the verification path does not draw blinding randomness.
- `HidingBackend::deterministic_config(seed)` exists for reproducible test snapshots.
  It must not be used in production.
- Round constants are derived deterministically from `params_seed` via `SmallRng`.
  This is standard practice in Plonky3 and does not affect hiding security.

## Status

This is a reference implementation, not a production protocol.

- The code has **not been audited**.
- Proof bundles support `postcard` serialization for size measurement and
  roundtrip testing. This is **not a stable wire format** -- do not persist
  or exchange proofs across crate versions.
- The API may change in future versions.

## Requirements

- Rust >= 1.85 (edition 2024)
- Plonky3 0.5.x

## License

MIT OR Apache-2.0
