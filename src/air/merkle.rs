use alloc::vec;
use alloc::vec::Vec;
use core::array;
use core::borrow::Borrow;

extern crate alloc;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::GenericPoseidon2LinearLayersBabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{Poseidon2Cols, generate_trace_rows, num_cols};
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};

use super::{
    DIGEST_WIDTH, FieldElement, HALF_FULL_ROUNDS, PARTIAL_ROUNDS, Poseidon2Params, SBOX_DEGREE,
    SBOX_REGISTERS, WIDTH, constrain_poseidon2, poseidon2_compress,
};

const P2_NUM_COLS: usize =
    num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();

/// Proves Merkle tree inclusion without revealing the leaf, path, or
/// sibling values.
///
/// Uses a wide-trace layout: each row encodes one complete Merkle path.
/// Level 0 is the leaf level; level `depth - 1` produces the root.
/// The only public value is the root digest (`DIGEST_WIDTH` elements).
pub struct MerkleInclusionAir {
    depth: usize,
    params: Poseidon2Params<FieldElement>,
}

impl MerkleInclusionAir {
    pub fn new(depth: usize, seed: u64) -> Self {
        assert!(depth >= 1, "Merkle depth must be at least 1");
        let mut rng = SmallRng::seed_from_u64(seed);
        let params = Poseidon2Params::from_rng(&mut rng);
        Self { depth, params }
    }

    pub fn from_params(depth: usize, params: Poseidon2Params<FieldElement>) -> Self {
        assert!(depth >= 1, "Merkle depth must be at least 1");
        Self { depth, params }
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn params(&self) -> &Poseidon2Params<FieldElement> {
        &self.params
    }

    fn row_width(&self) -> usize {
        self.depth * P2_NUM_COLS + self.depth
    }

    /// Generates a witness proving that `leaf` is at position `leaf_index`
    /// in a Merkle tree with the given `siblings` along the authentication path.
    pub fn generate_witness(
        &self,
        leaf: [FieldElement; DIGEST_WIDTH],
        siblings: &[[FieldElement; DIGEST_WIDTH]],
        leaf_index: u64,
        log_blowup: usize,
    ) -> MerkleInclusionWitness {
        assert_eq!(siblings.len(), self.depth);

        let mut current_hash = leaf;
        let mut level_inputs: Vec<[FieldElement; WIDTH]> = Vec::with_capacity(self.depth);
        let mut path_bits: Vec<FieldElement> = Vec::with_capacity(self.depth);

        for (level, sibling) in siblings.iter().enumerate() {
            let bit = (leaf_index >> level) & 1;
            let is_right = bit == 1;
            path_bits.push(if is_right {
                FieldElement::ONE
            } else {
                FieldElement::ZERO
            });

            let mut state = [FieldElement::ZERO; WIDTH];
            if is_right {
                state[..DIGEST_WIDTH].copy_from_slice(sibling);
                state[DIGEST_WIDTH..].copy_from_slice(&current_hash);
            } else {
                state[..DIGEST_WIDTH].copy_from_slice(&current_hash);
                state[DIGEST_WIDTH..].copy_from_slice(sibling);
            }
            level_inputs.push(state);

            current_hash = poseidon2_compress::<FieldElement, GenericPoseidon2LinearLayersBabyBear>(
                &array::from_fn(|i| state[i]),
                &array::from_fn(|i| state[i + DIGEST_WIDTH]),
                &self.params,
            );
        }

        let root = current_hash;
        let row_width = self.row_width();
        let num_rows = 2usize;
        let total_len = num_rows * row_width;
        let mut trace_vals = vec![FieldElement::ZERO; total_len << log_blowup];
        trace_vals.truncate(total_len);
        trace_vals.resize(total_len, FieldElement::ZERO);

        // Row 0: the real witness.
        for level in 0..self.depth {
            let offset = level * P2_NUM_COLS;
            let level_trace = generate_trace_rows::<
                FieldElement,
                GenericPoseidon2LinearLayersBabyBear,
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >(
                vec![level_inputs[level]],
                &self.params.to_round_constants(),
                0,
            );

            // Copy the single row of the level trace into row 0
            let src = level_trace.values.as_slice();
            trace_vals[offset..offset + P2_NUM_COLS].copy_from_slice(&src[..P2_NUM_COLS]);

            let bit_offset = self.depth * P2_NUM_COLS + level;
            trace_vals[bit_offset] = path_bits[level];
        }

        // Padding rows: fill with valid Poseidon2 permutations per level.
        let mut pad_rng = SmallRng::seed_from_u64(0xbeef);
        for row in 1..num_rows {
            let row_start = row * row_width;
            for level in 0..self.depth {
                let offset = row_start + level * P2_NUM_COLS;
                let dummy_input: [FieldElement; WIDTH] = pad_rng.random();

                let dummy_trace =
                    generate_trace_rows::<
                        FieldElement,
                        GenericPoseidon2LinearLayersBabyBear,
                        WIDTH,
                        SBOX_DEGREE,
                        SBOX_REGISTERS,
                        HALF_FULL_ROUNDS,
                        PARTIAL_ROUNDS,
                    >(vec![dummy_input], &self.params.to_round_constants(), 0);

                let src = dummy_trace.values.as_slice();
                trace_vals[offset..offset + P2_NUM_COLS].copy_from_slice(&src[..P2_NUM_COLS]);
            }
        }

        // Extend capacity for blowup without overwriting data.
        let final_capacity = total_len << log_blowup;
        trace_vals.reserve(final_capacity.saturating_sub(trace_vals.len()));

        MerkleInclusionWitness {
            trace: RowMajorMatrix::new(trace_vals, row_width),
            public_values: root.to_vec(),
        }
    }
}

pub struct MerkleInclusionWitness {
    pub trace: RowMajorMatrix<FieldElement>,
    pub public_values: Vec<FieldElement>,
}

// ---------------------------------------------------------------------------
// AIR trait implementations
// ---------------------------------------------------------------------------

impl BaseAir<FieldElement> for MerkleInclusionAir {
    fn width(&self) -> usize {
        self.row_width()
    }

    fn num_public_values(&self) -> usize {
        DIGEST_WIDTH
    }
}

impl<AB> Air<AB> for MerkleInclusionAir
where
    AB: AirBuilder<F = FieldElement>,
    GenericPoseidon2LinearLayersBabyBear: GenericPoseidon2LinearLayers<WIDTH>,
{
    fn eval(&self, builder: &mut AB) {
        // Snapshot public values before we start mutating the builder.
        let pis: Vec<AB::PublicVar> = builder.public_values().to_vec();

        // Snapshot all column variables we need.
        let main = builder.main();
        let local = main.current_slice();

        let mut level_p2_inputs: Vec<[AB::Var; WIDTH]> = Vec::with_capacity(self.depth);
        let mut level_p2_outputs: Vec<[AB::Var; DIGEST_WIDTH]> = Vec::with_capacity(self.depth);
        let mut level_bits: Vec<AB::Var> = Vec::with_capacity(self.depth);

        for level in 0..self.depth {
            let offset = level * P2_NUM_COLS;
            let p2: &Poseidon2Cols<
                AB::Var,
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            > = local[offset..offset + P2_NUM_COLS].borrow();

            level_p2_inputs.push(p2.inputs);
            let out = p2.ending_full_rounds[HALF_FULL_ROUNDS - 1].post;
            level_p2_outputs.push(core::array::from_fn(|j| out[j]));
            level_bits.push(local[self.depth * P2_NUM_COLS + level]);
        }

        // Drop the immutable borrows before calling builder mutably.
        drop(main);

        // Now apply constraints.
        for level in 0..self.depth {
            let offset = level * P2_NUM_COLS;

            // Re-borrow the p2 columns for Poseidon2 constraint evaluation.
            let main = builder.main();
            let local_slice = main.current_slice();
            let p2: &Poseidon2Cols<
                AB::Var,
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            > = local_slice[offset..offset + P2_NUM_COLS].borrow();

            constrain_poseidon2::<AB, GenericPoseidon2LinearLayersBabyBear>(
                builder,
                p2,
                &self.params,
            );

            let bit: AB::Expr = level_bits[level].into();
            builder.assert_zero(bit.clone() * (bit.clone() - AB::Expr::ONE));

            if level > 0 {
                let prev_output = &level_p2_outputs[level - 1];
                let inputs = &level_p2_inputs[level];

                for j in 0..DIGEST_WIDTH {
                    let left: AB::Expr = inputs[j].into();
                    let right: AB::Expr = inputs[j + DIGEST_WIDTH].into();
                    let prev_out: AB::Expr = prev_output[j].into();
                    let expected = left.clone() + bit.clone() * (right - left);
                    builder.when_first_row().assert_eq(prev_out, expected);
                }
            }

            if level == self.depth - 1 {
                for j in 0..DIGEST_WIDTH {
                    builder
                        .when_first_row()
                        .assert_eq(level_p2_outputs[level][j], pis[j].into());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air::poseidon2_compress;
    use crate::backend::{HidingBackend, StandardBackend};
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;
    use p3_uni_stark::{prove, verify};

    type MerkleFixture = (
        [BabyBear; DIGEST_WIDTH],
        Vec<[BabyBear; DIGEST_WIDTH]>,
        u64,
        [BabyBear; DIGEST_WIDTH],
        Poseidon2Params<BabyBear>,
    );

    fn make_tree(depth: usize, seed: u64) -> MerkleFixture {
        let mut rng = SmallRng::seed_from_u64(seed);
        let params = Poseidon2Params::from_rng(&mut rng);

        let leaf: [BabyBear; DIGEST_WIDTH] = array::from_fn(|i| BabyBear::from_u64(i as u64 + 1));
        let leaf_index: u64 = 3;

        let mut siblings = Vec::with_capacity(depth);
        let mut current = leaf;
        for level in 0..depth {
            let sibling: [BabyBear; DIGEST_WIDTH] =
                array::from_fn(|i| BabyBear::from_u64((level * 100 + i + 50) as u64));
            let is_right = ((leaf_index >> level) & 1) == 1;
            let (left, right) = if is_right {
                (&sibling, &current)
            } else {
                (&current, &sibling)
            };
            current = poseidon2_compress::<BabyBear, GenericPoseidon2LinearLayersBabyBear>(
                left, right, &params,
            );
            siblings.push(sibling);
        }

        (leaf, siblings, leaf_index, current, params)
    }

    #[test]
    fn standard_merkle_roundtrip() {
        let depth = 4;
        let (leaf, siblings, leaf_index, _root, params) = make_tree(depth, 42);
        let air = MerkleInclusionAir::from_params(depth, params);
        let config = StandardBackend::config();
        let witness = air.generate_witness(leaf, &siblings, leaf_index, 1);

        let proof = prove(&config, &air, witness.trace, &witness.public_values);
        verify(&config, &air, &proof, &witness.public_values)
            .expect("valid standard Merkle proof should verify");
    }

    #[test]
    fn hiding_merkle_roundtrip() {
        let depth = 4;
        let (leaf, siblings, leaf_index, _root, params) = make_tree(depth, 42);
        let air = MerkleInclusionAir::from_params(depth, params);
        let config = HidingBackend::config();
        let witness = air.generate_witness(leaf, &siblings, leaf_index, 2);

        let proof = prove(&config, &air, witness.trace, &witness.public_values);
        verify(&config, &air, &proof, &witness.public_values)
            .expect("valid hiding Merkle proof should verify");
    }

    #[test]
    fn tampered_root_rejected_by_verifier() {
        let depth = 4;
        let (leaf, siblings, leaf_index, _root, params) = make_tree(depth, 42);
        let air = MerkleInclusionAir::from_params(depth, params);
        let config = StandardBackend::config();
        let witness = air.generate_witness(leaf, &siblings, leaf_index, 1);

        let proof = prove(&config, &air, witness.trace, &witness.public_values);

        let mut bad_pv = witness.public_values.clone();
        bad_pv[0] += FieldElement::ONE;

        assert!(
            verify(&config, &air, &proof, &bad_pv).is_err(),
            "verifier should reject proof when root is tampered"
        );
    }
}
