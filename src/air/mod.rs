pub mod preimage;
pub mod merkle;

use core::array;

use p3_baby_bear::BabyBear;
use p3_field::{PrimeCharacteristicRing, PrimeField};
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::RoundConstants;
use rand::Rng;
use rand::distr::{Distribution, StandardUniform};

pub const WIDTH: usize = 16;
pub const SBOX_DEGREE: u64 = 7;
pub const SBOX_REGISTERS: usize = 1;
pub const HALF_FULL_ROUNDS: usize = 4;
pub const PARTIAL_ROUNDS: usize = 13;
pub const DIGEST_WIDTH: usize = WIDTH / 2;

pub type FieldElement = BabyBear;

#[derive(Clone, Debug)]
pub struct Poseidon2Params<F: Copy> {
    pub beginning_full_round_constants: [[F; WIDTH]; HALF_FULL_ROUNDS],
    pub partial_round_constants: [F; PARTIAL_ROUNDS],
    pub ending_full_round_constants: [[F; WIDTH]; HALF_FULL_ROUNDS],
}

impl<F: Copy> Poseidon2Params<F>
where
    StandardUniform: Distribution<F> + Distribution<[F; WIDTH]>,
{
    pub fn from_rng<R: Rng>(rng: &mut R) -> Self {
        use rand::RngExt;
        Self {
            beginning_full_round_constants: array::from_fn(|_| rng.random()),
            partial_round_constants: array::from_fn(|_| rng.random()),
            ending_full_round_constants: array::from_fn(|_| rng.random()),
        }
    }
}

impl<F: Copy + p3_field::PrimeCharacteristicRing> Poseidon2Params<F> {
    pub fn to_round_constants(&self) -> RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> {
        RoundConstants::new(
            self.beginning_full_round_constants,
            self.partial_round_constants,
            self.ending_full_round_constants,
        )
    }
}

/// Computes the full Poseidon2 permutation over a WIDTH-element state.
pub fn poseidon2_permute<
    F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<WIDTH>,
>(
    mut state: [F; WIDTH],
    params: &Poseidon2Params<F>,
) -> [F; WIDTH] {
    LinearLayers::external_linear_layer(&mut state);

    for rc in &params.beginning_full_round_constants {
        for (s, c) in state.iter_mut().zip(rc) {
            *s += *c;
            *s = sbox(*s);
        }
        LinearLayers::external_linear_layer(&mut state);
    }

    for &rc in &params.partial_round_constants {
        state[0] += rc;
        state[0] = sbox(state[0]);
        LinearLayers::internal_linear_layer(&mut state);
    }

    for rc in &params.ending_full_round_constants {
        for (s, c) in state.iter_mut().zip(rc) {
            *s += *c;
            *s = sbox(*s);
        }
        LinearLayers::external_linear_layer(&mut state);
    }

    state
}

/// 2-to-1 compression: hashes two DIGEST_WIDTH-element digests into one.
pub fn poseidon2_compress<
    F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<WIDTH>,
>(
    left: &[F; DIGEST_WIDTH],
    right: &[F; DIGEST_WIDTH],
    params: &Poseidon2Params<F>,
) -> [F; DIGEST_WIDTH] {
    let mut state = [F::ZERO; WIDTH];
    state[..DIGEST_WIDTH].copy_from_slice(left);
    state[DIGEST_WIDTH..].copy_from_slice(right);
    let output = poseidon2_permute::<F, LinearLayers>(state, params);
    array::from_fn(|i| output[i])
}

#[inline]
fn sbox<F: PrimeField>(x: F) -> F {
    let x3 = x.cube();
    x3 * x3 * x
}

// ---------------------------------------------------------------------------
// Poseidon2 constraint gadget (re-implements p3-poseidon2-air's eval logic
// so we can call it from custom column layouts).
// ---------------------------------------------------------------------------

use p3_air::AirBuilder;
use p3_poseidon2_air::{Poseidon2Cols, FullRound, PartialRound, SBox};

pub fn constrain_poseidon2<
    AB: AirBuilder,
    LinearLayers: GenericPoseidon2LinearLayers<WIDTH>,
>(
    builder: &mut AB,
    local: &Poseidon2Cols<AB::Var, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
    params: &Poseidon2Params<AB::F>,
) where
    AB::F: Copy,
{
    let mut state: [AB::Expr; WIDTH] = local.inputs.map(|x| x.into());

    LinearLayers::external_linear_layer(&mut state);

    for (round, rc) in params.beginning_full_round_constants.iter().enumerate() {
        eval_full_round::<AB, LinearLayers>(
            &mut state,
            &local.beginning_full_rounds[round],
            rc,
            builder,
        );
    }

    for (round, rc) in params.partial_round_constants.iter().enumerate() {
        eval_partial_round::<AB, LinearLayers>(
            &mut state,
            &local.partial_rounds[round],
            rc,
            builder,
        );
    }

    for (round, rc) in params.ending_full_round_constants.iter().enumerate() {
        eval_full_round::<AB, LinearLayers>(
            &mut state,
            &local.ending_full_rounds[round],
            rc,
            builder,
        );
    }
}

fn eval_full_round<
    AB: AirBuilder,
    LinearLayers: GenericPoseidon2LinearLayers<WIDTH>,
>(
    state: &mut [AB::Expr; WIDTH],
    full_round: &FullRound<AB::Var, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>,
    round_constants: &[AB::F; WIDTH],
    builder: &mut AB,
) where
    AB::F: Copy,
{
    for (i, (s, r)) in state.iter_mut().zip(round_constants.iter()).enumerate() {
        *s = s.clone() + AB::Expr::from(*r);
        eval_sbox_constraint(&full_round.sbox[i], s, builder);
    }
    LinearLayers::external_linear_layer(state);
    for (state_i, post_i) in state.iter_mut().zip(full_round.post) {
        builder.assert_eq(state_i.clone(), post_i);
        *state_i = post_i.into();
    }
}

fn eval_partial_round<
    AB: AirBuilder,
    LinearLayers: GenericPoseidon2LinearLayers<WIDTH>,
>(
    state: &mut [AB::Expr; WIDTH],
    partial_round: &PartialRound<AB::Var, WIDTH, SBOX_DEGREE, SBOX_REGISTERS>,
    round_constant: &AB::F,
    builder: &mut AB,
) where
    AB::F: Copy,
{
    state[0] = state[0].clone() + AB::Expr::from(*round_constant);
    eval_sbox_constraint(&partial_round.sbox, &mut state[0], builder);
    builder.assert_eq(state[0].clone(), partial_round.post_sbox);
    state[0] = partial_round.post_sbox.into();
    LinearLayers::internal_linear_layer(state);
}

fn eval_sbox_constraint<AB: AirBuilder>(
    sbox_witness: &SBox<AB::Var, SBOX_DEGREE, SBOX_REGISTERS>,
    x: &mut AB::Expr,
    builder: &mut AB,
) {
    // degree 7, 1 register: witness stores x^3
    let committed_x3: AB::Expr = sbox_witness.0[0].into();
    builder.assert_eq(committed_x3.clone(), x.cube());
    *x = committed_x3.square() * x.clone();
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_baby_bear::GenericPoseidon2LinearLayersBabyBear;
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    type LinLayers = GenericPoseidon2LinearLayersBabyBear;

    #[test]
    fn permute_is_deterministic() {
        let mut rng = SmallRng::seed_from_u64(42);
        let params = Poseidon2Params::<BabyBear>::from_rng(&mut rng);
        let input: [BabyBear; WIDTH] = array::from_fn(|i| BabyBear::from_u64(i as u64 + 1));

        let out1 = poseidon2_permute::<BabyBear, LinLayers>(input, &params);
        let out2 = poseidon2_permute::<BabyBear, LinLayers>(input, &params);
        assert_eq!(out1, out2);
    }

    #[test]
    fn different_inputs_yield_different_outputs() {
        let mut rng = SmallRng::seed_from_u64(42);
        let params = Poseidon2Params::<BabyBear>::from_rng(&mut rng);

        let a: [BabyBear; WIDTH] = array::from_fn(|i| BabyBear::from_u64(i as u64));
        let b: [BabyBear; WIDTH] = array::from_fn(|i| BabyBear::from_u64(i as u64 + 100));

        let out_a = poseidon2_permute::<BabyBear, LinLayers>(a, &params);
        let out_b = poseidon2_permute::<BabyBear, LinLayers>(b, &params);
        assert_ne!(out_a, out_b);
    }

    #[test]
    fn compress_is_deterministic() {
        let mut rng = SmallRng::seed_from_u64(42);
        let params = Poseidon2Params::<BabyBear>::from_rng(&mut rng);

        let left: [BabyBear; DIGEST_WIDTH] =
            array::from_fn(|i| BabyBear::from_u64(i as u64 + 1));
        let right: [BabyBear; DIGEST_WIDTH] =
            array::from_fn(|i| BabyBear::from_u64(i as u64 + 100));

        let c1 = poseidon2_compress::<BabyBear, LinLayers>(&left, &right, &params);
        let c2 = poseidon2_compress::<BabyBear, LinLayers>(&left, &right, &params);
        assert_eq!(c1, c2);
    }
}
