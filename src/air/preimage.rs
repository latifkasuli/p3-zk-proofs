use alloc::vec::Vec;
use core::borrow::Borrow;

extern crate alloc;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::GenericPoseidon2LinearLayersBabyBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{Poseidon2Air, Poseidon2Cols, generate_trace_rows};
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};

use super::{
    FieldElement, Poseidon2Params, poseidon2_permute,
    WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS,
};

type InnerAir = Poseidon2Air<
    FieldElement,
    GenericPoseidon2LinearLayersBabyBear,
    WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS,
>;

/// Proves knowledge of a Poseidon2 preimage without revealing it.
///
/// Given public hash output `y`, the prover demonstrates they know `x`
/// such that `Poseidon2(x) = y`. The preimage `x` is committed inside
/// the trace and hidden by the polynomial commitment scheme.
pub struct PreimageAir {
    inner: InnerAir,
    params: Poseidon2Params<FieldElement>,
}

impl PreimageAir {
    /// Creates a new PreimageAir with deterministic round constants
    /// derived from `seed`.
    pub fn new(seed: u64) -> Self {
        let mut rng = SmallRng::seed_from_u64(seed);
        let params = Poseidon2Params::from_rng(&mut rng);
        let inner = InnerAir::new(params.to_round_constants());
        Self { inner, params }
    }

    pub fn from_params(params: Poseidon2Params<FieldElement>) -> Self {
        let inner = InnerAir::new(params.to_round_constants());
        Self { inner, params }
    }

    pub fn params(&self) -> &Poseidon2Params<FieldElement> {
        &self.params
    }

    /// Generates a trace for proving knowledge of `preimage`.
    ///
    /// Returns the trace matrix and the public values (hash output)
    /// that the verifier will check against.
    pub fn generate_witness(
        &self,
        preimage: [FieldElement; WIDTH],
        log_blowup: usize,
    ) -> PreimageWitness {
        let hash_output =
            poseidon2_permute::<FieldElement, GenericPoseidon2LinearLayersBabyBear>(
                preimage, &self.params,
            );

        let min_rows = 2usize;
        let mut inputs = Vec::with_capacity(min_rows);
        inputs.push(preimage);

        let mut pad_rng = SmallRng::seed_from_u64(0xdead);
        for _ in 1..min_rows {
            inputs.push(pad_rng.random());
        }

        let trace = generate_trace_rows::<
            FieldElement,
            GenericPoseidon2LinearLayersBabyBear,
            WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS,
        >(inputs, &self.params.to_round_constants(), log_blowup);

        PreimageWitness {
            trace,
            public_values: hash_output.to_vec(),
        }
    }
}

/// The witness produced by `PreimageAir::generate_witness`.
pub struct PreimageWitness {
    pub trace: RowMajorMatrix<FieldElement>,
    pub public_values: Vec<FieldElement>,
}

// ---------------------------------------------------------------------------
// AIR trait implementations
// ---------------------------------------------------------------------------

impl BaseAir<FieldElement> for PreimageAir {
    fn width(&self) -> usize {
        self.inner.width()
    }

    fn num_public_values(&self) -> usize {
        WIDTH
    }
}

impl<AB> Air<AB> for PreimageAir
where
    AB: AirBuilder<F = FieldElement>,
    GenericPoseidon2LinearLayersBabyBear: GenericPoseidon2LinearLayers<WIDTH>,
{
    fn eval(&self, builder: &mut AB) {
        Air::<AB>::eval(&self.inner, builder);

        let main = builder.main();
        let local: &Poseidon2Cols<
            AB::Var, WIDTH, SBOX_DEGREE, SBOX_REGISTERS,
            HALF_FULL_ROUNDS, PARTIAL_ROUNDS,
        > = main.current_slice().borrow();

        let output: [AB::Var; WIDTH] = local.ending_full_rounds[HALF_FULL_ROUNDS - 1].post;

        let pis: Vec<AB::PublicVar> = builder.public_values().to_vec();

        for (out_col, pi) in output.iter().zip(pis.iter()) {
            builder.when_first_row().assert_eq(*out_col, (*pi).into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;
    use p3_uni_stark::{prove, verify};
    use crate::backend::{StandardBackend, HidingBackend};

    fn test_preimage() -> [BabyBear; WIDTH] {
        core::array::from_fn(|i| BabyBear::from_u64((i + 1) as u64))
    }

    #[test]
    fn standard_proof_roundtrip() {
        let air = PreimageAir::new(42);
        let config = StandardBackend::config();
        let witness = air.generate_witness(test_preimage(), 1);

        let proof = prove(&config, &air, witness.trace, &witness.public_values);
        verify(&config, &air, &proof, &witness.public_values)
            .expect("valid standard proof should verify");
    }

    #[test]
    fn hiding_proof_roundtrip() {
        let air = PreimageAir::new(42);
        let config = HidingBackend::config();
        let witness = air.generate_witness(test_preimage(), 2);

        let proof = prove(&config, &air, witness.trace, &witness.public_values);
        verify(&config, &air, &proof, &witness.public_values)
            .expect("valid hiding proof should verify");
    }

    #[test]
    fn tampered_public_values_rejected_by_verifier() {
        let air = PreimageAir::new(42);
        let config = StandardBackend::config();
        let witness = air.generate_witness(test_preimage(), 1);

        let proof = prove(&config, &air, witness.trace, &witness.public_values);

        let mut bad_pv = witness.public_values.clone();
        bad_pv[0] += FieldElement::ONE;

        assert!(
            verify(&config, &air, &proof, &bad_pv).is_err(),
            "verifier should reject proof when public values are tampered"
        );
    }
}
