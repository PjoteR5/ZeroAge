#[allow(unused_imports)]
use ark_ff::{Field, One, Zero};
use crate::circuit::layered::CircuitLayer;
use crate::sumcheck::univariate::UnivariateDegree2;

/// Verifier protokołu Sumcheck dla pojedynczej warstwy obwodu (Rozdział 2.1, Protokół 2.2).
pub struct SumcheckVerifier<F: Field> {
    pub layer: CircuitLayer<F>,
    pub alpha: F,
    pub r_out_0: Vec<F>,
    pub r_out_1: Vec<F>,
    /// Aktualna deklarowana suma (na początku Y = alpha*c_0 + (1-alpha)*c_1)
    pub current_claim: F,
    pub omega_in: usize,
    pub challenges: Vec<F>,
}

impl<F: Field> SumcheckVerifier<F> {
    pub fn new(
        layer: CircuitLayer<F>,
        alpha: F,
        r_out_0: Vec<F>,
        r_out_1: Vec<F>,
        claim_0: F,
        claim_1: F,
    ) -> Self {
        let in_width = layer.in_width;
        let mut next_pow2 = in_width.next_power_of_two();
        if next_pow2 < 2 {
            next_pow2 = 2;
        }
        let omega_in = next_pow2.trailing_zeros() as usize;

        // Y = alpha * c_0 + (1 - alpha) * c_1
        let current_claim = alpha * claim_0 + (F::one() - alpha) * claim_1;

        Self {
            layer,
            alpha,
            r_out_0,
            r_out_1,
            current_claim,
            omega_in,
            challenges: Vec::with_capacity(2 * omega_in),
        }
    }

    pub fn total_rounds(&self) -> usize {
        2 * self.omega_in
    }

    /// Weryfikuje wielomian rundy g_k(X) i aktualizuje roszczenie:
    /// 1. Sprawdza czy g_k(0) + g_k(1) == current_claim
    /// 2. Ustawia new_claim = g_k(challenge)
    pub fn verify_round(&mut self, round_poly: &UnivariateDegree2<F>, challenge: F) -> bool {
        if !round_poly.check_sum(&self.current_claim) {
            return false;
        }
        self.current_claim = round_poly.evaluate(&challenge);
        self.challenges.push(challenge);
        true
    }

    /// Zwraca punkty (L, R) po zakończeniu wszystkich rund
    pub fn get_final_points(&self) -> (Vec<F>, Vec<F>) {
        assert_eq!(
            self.challenges.len(),
            self.total_rounds(),
            "Nie wszystkie rundy zostały zakończone"
        );
        let l = self.challenges[0..self.omega_in].to_vec();
        let r = self.challenges[self.omega_in..2 * self.omega_in].to_vec();
        (l, r)
    }

    /// Sprawdzenie końcowe weryfikatora (Krok 2e w Protokole 2.2 z ZKP.pdf):
    /// Sprawdza czy y == [alpha * Q(r_out_0, l, r) + (1-alpha) * Q(r_out_1, l, r)] * c_{j+1,0} * c_{j+1,1}
    pub fn verify_final_check(&self, c_next_0: F, c_next_1: F) -> bool {
        let (l, r) = self.get_final_points();

        let q0 = self.layer.eval_wiring_predicate(&self.r_out_0, &l, &r);
        let q1 = self.layer.eval_wiring_predicate(&self.r_out_1, &l, &r);
        let q_term = self.alpha * q0 + (F::one() - self.alpha) * q1;

        let expected_y = q_term * c_next_0 * c_next_1;
        self.current_claim == expected_y
    }
}

#[cfg(test)]
#[allow(non_local_definitions)]
mod tests {
    use super::*;
    use crate::circuit::gate::QuadGate;
    use crate::sumcheck::prover::SumcheckProver;
    use ark_ff::{Fp64, MontBackend, MontConfig, Zero};

    #[derive(MontConfig)]
    #[modulus = "17"]
    #[generator = "3"]
    pub struct FqConfig;
    pub type F17 = Fp64<MontBackend<FqConfig, 1>>;

    #[test]
    fn test_sumcheck_layer_protocol() {
        // Warstwa j: łączy warstwę wejściową (szerokość 4) z wyjściową (szerokość 2)
        // Bramka: V_0[1] = V_1[1] * V_1[2] (mnożenie)
        let gate = QuadGate::mul(1, 1, 2);
        let layer = CircuitLayer::<F17>::new(0, 4, 2, vec![gate]);

        // Przewody wejściowe V_1: [V[0]=1, V[1]=3, V[2]=5, V[3]=0]
        let v_in = vec![F17::one(), F17::from(3u64), F17::from(5u64), F17::zero()];
        let _v_out = layer.evaluate(&v_in); // V_0 = [1, 3*5 = 15]

        // Punkty wyjściowe r_out: dla warstwy wyjściowej o szerokości 2 mamy omega_0 = 1
        // r_out_0 = [0] -> V_0[0] = 1
        // r_out_1 = [1] -> V_0[1] = 15
        let r_out_0 = vec![F17::zero()];
        let r_out_1 = vec![F17::one()];
        let claim_0 = F17::one();        // V_0(0) = 1
        let claim_1 = F17::from(15u64); // V_0(1) = 15

        let alpha = F17::from(7u64); // Losowa waga wygenerowana przez weryfikatora

        let mut prover = SumcheckProver::<F17>::new(
            layer.clone(),
            alpha,
            r_out_0.clone(),
            r_out_1.clone(),
            &v_in,
        );

        let mut verifier = SumcheckVerifier::<F17>::new(
            layer,
            alpha,
            r_out_0,
            r_out_1,
            claim_0,
            claim_1,
        );

        let rounds = prover.total_rounds(); // 2 * omega_in = 2 * 2 = 4 rundy
        assert_eq!(rounds, 4);

        // Przebieg interaktywny 4 rund protokołu:
        let test_challenges = [
            F17::from(2u64),
            F17::from(3u64),
            F17::from(5u64),
            F17::from(7u64),
        ];

        for round_idx in 0..rounds {
            // Prover generuje wielomian stopnia 2
            let round_poly = prover.compute_round_poly();

            // Verifier sprawdza i podaje wyzwanie
            let challenge = test_challenges[round_idx];
            let round_ok = verifier.verify_round(&round_poly, challenge);
            assert!(round_ok, "Runda {} nie przeszła weryfikacji", round_idx);

            // Prover przyjmuje wyzwanie
            prover.receive_challenge(challenge);
        }

        // Końcowe sprawdzenie roszczeń na wejściach
        let (c_next_0, c_next_1) = prover.compute_next_claims();
        let final_ok = verifier.verify_final_check(c_next_0, c_next_1);
        assert!(final_ok, "Końcowe sprawdzenie Verifiera nie powiodło się");
    }
}
