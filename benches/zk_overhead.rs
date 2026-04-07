use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::{prove, verify};
use p3_zk_proofs::air::merkle::MerkleInclusionAir;
use p3_zk_proofs::air::preimage::PreimageAir;
use p3_zk_proofs::backend::{HidingBackend, StandardBackend};
use p3_zk_proofs::{
    DIGEST_WIDTH, WIDTH, prove_merkle_inclusion_hiding, prove_merkle_inclusion_standard,
    prove_preimage_hiding, prove_preimage_standard, verify_merkle_inclusion, verify_preimage,
};

// ---------------------------------------------------------------------------
// api/* -- measures end-to-end one-call API latency (setup + prove + verify)
// ---------------------------------------------------------------------------

fn bench_api_preimage(c: &mut Criterion) {
    let preimage: [BabyBear; WIDTH] = core::array::from_fn(|i| BabyBear::from_u64((i + 1) as u64));
    let seed = 42;

    c.bench_function("api/preimage/standard/prove", |b| {
        b.iter(|| prove_preimage_standard(preimage, seed))
    });

    let proof = prove_preimage_standard(preimage, seed);
    c.bench_function("api/preimage/standard/verify", |b| {
        b.iter(|| verify_preimage(&proof).unwrap())
    });

    c.bench_function("api/preimage/hiding/prove", |b| {
        b.iter(|| prove_preimage_hiding(preimage, seed))
    });

    let proof = prove_preimage_hiding(preimage, seed);
    c.bench_function("api/preimage/hiding/verify", |b| {
        b.iter(|| verify_preimage(&proof).unwrap())
    });
}

fn bench_api_merkle(c: &mut Criterion) {
    let (leaf, siblings, index, depth, seed) = merkle_fixture(8);

    c.bench_function("api/merkle_d8/standard/prove", |b| {
        b.iter(|| prove_merkle_inclusion_standard(leaf, &siblings, index, depth, seed))
    });

    let proof = prove_merkle_inclusion_standard(leaf, &siblings, index, depth, seed);
    c.bench_function("api/merkle_d8/standard/verify", |b| {
        b.iter(|| verify_merkle_inclusion(&proof).unwrap())
    });

    c.bench_function("api/merkle_d8/hiding/prove", |b| {
        b.iter(|| prove_merkle_inclusion_hiding(leaf, &siblings, index, depth, seed))
    });

    let proof = prove_merkle_inclusion_hiding(leaf, &siblings, index, depth, seed);
    c.bench_function("api/merkle_d8/hiding/verify", |b| {
        b.iter(|| verify_merkle_inclusion(&proof).unwrap())
    });
}

// ---------------------------------------------------------------------------
// core/* -- measures only prove/verify with pre-built AIR, config, witness
// ---------------------------------------------------------------------------

fn bench_core_preimage(c: &mut Criterion) {
    let preimage: [BabyBear; WIDTH] = core::array::from_fn(|i| BabyBear::from_u64((i + 1) as u64));
    let seed = 42;
    let air = PreimageAir::new(seed);

    // Standard
    {
        let config = StandardBackend::config();
        let witness = air.generate_witness(preimage, 1);
        let pv = witness.public_values.clone();

        c.bench_function("core/preimage/standard/prove", |b| {
            b.iter_batched(
                || air.generate_witness(preimage, 1),
                |w| prove(&config, &air, w.trace, &w.public_values),
                criterion::BatchSize::SmallInput,
            )
        });

        let proof = prove(&config, &air, witness.trace, &pv);
        c.bench_function("core/preimage/standard/verify", |b| {
            b.iter(|| verify(&config, &air, &proof, &pv).unwrap())
        });
    }

    // Hiding
    {
        let config = HidingBackend::deterministic_config(0);
        let witness = air.generate_witness(preimage, 2);
        let pv = witness.public_values.clone();

        c.bench_function("core/preimage/hiding/prove", |b| {
            b.iter_batched(
                || air.generate_witness(preimage, 2),
                |w| prove(&config, &air, w.trace, &w.public_values),
                criterion::BatchSize::SmallInput,
            )
        });

        let proof = prove(&config, &air, witness.trace, &pv);
        let v_config = HidingBackend::verifier_config();
        c.bench_function("core/preimage/hiding/verify", |b| {
            b.iter(|| verify(&v_config, &air, &proof, &pv).unwrap())
        });
    }
}

fn bench_core_merkle(c: &mut Criterion) {
    let (leaf, siblings, index, depth, seed) = merkle_fixture(8);
    let air = MerkleInclusionAir::new(depth, seed);

    // Standard
    {
        let config = StandardBackend::config();
        let witness = air.generate_witness(leaf, &siblings, index, 1);
        let pv = witness.public_values.clone();

        c.bench_function("core/merkle_d8/standard/prove", |b| {
            b.iter_batched(
                || air.generate_witness(leaf, &siblings, index, 1),
                |w| prove(&config, &air, w.trace, &w.public_values),
                criterion::BatchSize::SmallInput,
            )
        });

        let proof = prove(&config, &air, witness.trace, &pv);
        c.bench_function("core/merkle_d8/standard/verify", |b| {
            b.iter(|| verify(&config, &air, &proof, &pv).unwrap())
        });
    }

    // Hiding
    {
        let config = HidingBackend::deterministic_config(0);
        let witness = air.generate_witness(leaf, &siblings, index, 2);
        let pv = witness.public_values.clone();

        c.bench_function("core/merkle_d8/hiding/prove", |b| {
            b.iter_batched(
                || air.generate_witness(leaf, &siblings, index, 2),
                |w| prove(&config, &air, w.trace, &w.public_values),
                criterion::BatchSize::SmallInput,
            )
        });

        let proof = prove(&config, &air, witness.trace, &pv);
        let v_config = HidingBackend::verifier_config();
        c.bench_function("core/merkle_d8/hiding/verify", |b| {
            b.iter(|| verify(&v_config, &air, &proof, &pv).unwrap())
        });
    }
}

// ---------------------------------------------------------------------------
// core/merkle depth sweep -- scaling data across depths
// ---------------------------------------------------------------------------

fn bench_merkle_depth_sweep(c: &mut Criterion) {
    let mut group = c.benchmark_group("core/merkle_depth/standard/prove");
    for depth in [1, 4, 8, 16] {
        let (leaf, siblings, index, depth, seed) = merkle_fixture(depth);
        let air = MerkleInclusionAir::new(depth, seed);
        let config = StandardBackend::config();

        group.bench_with_input(BenchmarkId::from_parameter(depth), &depth, |b, _| {
            b.iter_batched(
                || air.generate_witness(leaf, &siblings, index, 1),
                |w| prove(&config, &air, w.trace, &w.public_values),
                criterion::BatchSize::SmallInput,
            )
        });
    }
    group.finish();
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn merkle_fixture(
    depth: usize,
) -> (
    [BabyBear; DIGEST_WIDTH],
    Vec<[BabyBear; DIGEST_WIDTH]>,
    u64,
    usize,
    u64,
) {
    let leaf: [BabyBear; DIGEST_WIDTH] =
        core::array::from_fn(|i| BabyBear::from_u64((i + 1) as u64));
    let siblings: Vec<[BabyBear; DIGEST_WIDTH]> = (0..depth)
        .map(|level| core::array::from_fn(|i| BabyBear::from_u64((level * 100 + i + 50) as u64)))
        .collect();
    (leaf, siblings, 42, depth, 7)
}

criterion_group!(
    benches,
    bench_api_preimage,
    bench_api_merkle,
    bench_core_preimage,
    bench_core_merkle,
    bench_merkle_depth_sweep,
);
criterion_main!(benches);
