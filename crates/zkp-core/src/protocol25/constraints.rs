use ark_ff::Field;
use crate::circuit::layered::eq_eval;
use crate::protocol25::pad::MaskedTranscript;

/// Współczynniki bazy Lagrange'a dla wielomianu stopnia 2 na węzłach {0, 1, 2}.
///
/// Dla punktu $r \in \mathbb{F}$:
/// $\lambda_r(0) = \frac{(r - 1)(r - 2)}{2}$
/// $\lambda_r(1) = r(2 - r)$
/// $\lambda_r(2) = \frac{r(r - 1)}{2}$
///
/// Wtedy dla dowolnego $p \in \mathbb{F}[X]_{\le 2}$:
/// $p(r) = \lambda_r(0) p(0) + \lambda_r(1) p(1) + \lambda_r(2) p(2) = \langle \lambda_r, (p(0), p(1), p(2)) \rangle$.
pub fn lagrange_eval_degree2<F: Field>(r: F) -> [F; 3] {
    let two = F::from(2u64);
    let two_inv = two.inverse().expect("2 musi być odwracalne w ciele o charakterystyce != 2");
    let one = F::from(1u64);

    let l0 = (r - one) * (r - two) * two_inv;
    let l1 = r * (two - r);
    let l2 = r * (r - one) * two_inv;

    [l0, l1, l2]
}

/// Pojedyncze ograniczenie liniowe w postaci iloczynu skalarnego:
/// $\langle \mathbf{a}, w' \rangle = b$.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinearConstraint<F: Field> {
    /// Wektor wag $\mathbf{a}$ o długości $|w'|$.
    pub weights: Vec<F>,
    /// Oczekiwana wartość skalarna $b$.
    pub target: F,
}

impl<F: Field> LinearConstraint<F> {
    /// Tworzy nowe ograniczenie liniowe.
    pub fn new(weights: Vec<F>, target: F) -> Self {
        Self { weights, target }
    }

    /// Oblicza ewaluację lewej strony dla zadanego rozszerzonego świadka $w'$.
    pub fn eval(&self, w_prime: &[F]) -> F {
        assert_eq!(
            self.weights.len(),
            w_prime.len(),
            "Wymiary wektora wag i świadka muszą być zgodne"
        );
        self.weights
            .iter()
            .zip(w_prime.iter())
            .map(|(&a, &w)| a * w)
            .sum()
    }

    /// Sprawdza, czy rozszerzony świadek $w'$ spełnia to ograniczenie:
    /// $\langle \mathbf{a}, w' \rangle \stackrel{?}{=} b$.
    pub fn is_satisfied(&self, w_prime: &[F]) -> bool {
        self.eval(w_prime) == self.target
    }
}

/// Ograniczenie kwadratowe na końcu protokołu Sumcheck (Strona 11 publikacji Frigo & shelat):
///
/// $$\langle \lambda_{r_\ell}, \text{pad}_\ell \rangle - Q \cdot W_L \cdot \text{pad}_R - Q \cdot W_R \cdot \text{pad}_L + Q \cdot \text{pad}_L \cdot \text{pad}_R = \langle \lambda_{r_\ell}, P_\ell \rangle - Q \cdot W_L \cdot W_R$$
///
/// Gdzie:
/// - Lewa strona operuje na tajnych maskach $\mathbf{pad} \subset w'$ (składniki liniowe + jeden składnik kwadratowy $\text{pad}_L \cdot \text{pad}_R$).
/// - Prawa strona składa się wyłącznie z publicznych wartości z transkryptu $T'$ oraz publicznej bramki $Q$.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuadraticConstraint<F: Field> {
    /// Indeks $\text{pad}_{\ell, 0}$ w wektorze $w'$
    pub idx_pad_ell_0: usize,
    /// Indeks $\text{pad}_{\ell, 1}$ w wektorze $w'$
    pub idx_pad_ell_1: usize,
    /// Indeks $\text{pad}_{\ell, 2}$ w wektorze $w'$
    pub idx_pad_ell_2: usize,
    /// Indeks $\text{pad}_L$ w wektorze $w'$
    pub idx_pad_l: usize,
    /// Indeks $\text{pad}_R$ w wektorze $w'$
    pub idx_pad_r: usize,

    /// Współczynniki liniowe: $[\lambda(0), \lambda(1), \lambda(2)]$
    pub coeff_pad_ell: [F; 3],
    /// Współczynnik przy $\text{pad}_L$: $-Q \cdot W_R$
    pub coeff_pad_l: F,
    /// Współczynnik przy $\text{pad}_R$: $-Q \cdot W_L$
    pub coeff_pad_r: F,
    /// Współczynnik kwadratowy przy $\text{pad}_L \cdot \text{pad}_R$: $Q$
    pub coeff_quad: F,

    /// Publiczna wartość docelowa: $\langle \lambda, P_\ell \rangle - Q \cdot W_L \cdot W_R$
    pub target: F,
}

impl<F: Field> QuadraticConstraint<F> {
    /// Oblicza ewaluację lewej strony dla zadanego rozszerzonego świadka $w'$.
    pub fn eval(&self, w_prime: &[F]) -> F {
        let pad_0 = w_prime[self.idx_pad_ell_0];
        let pad_1 = w_prime[self.idx_pad_ell_1];
        let pad_2 = w_prime[self.idx_pad_ell_2];
        let pad_l = w_prime[self.idx_pad_l];
        let pad_r = w_prime[self.idx_pad_r];

        let linear_part = self.coeff_pad_ell[0] * pad_0
            + self.coeff_pad_ell[1] * pad_1
            + self.coeff_pad_ell[2] * pad_2
            + self.coeff_pad_l * pad_l
            + self.coeff_pad_r * pad_r;

        let quad_part = self.coeff_quad * (pad_l * pad_r);

        linear_part + quad_part
    }

    /// Sprawdza, czy ograniczenie kwadratowe jest spełnione.
    pub fn is_satisfied(&self, w_prime: &[F]) -> bool {
        self.eval(w_prime) == self.target
    }
}

/// Zestaw wszystkich ograniczeń generowanych przez Weryfikatora w Protokole 2.5:
/// - Ograniczenia liniowe (sprawdzenie sumchecka, redukcja Lagrange'a, dopasowanie MLE wejść),
/// - Pojedyncze ograniczenie kwadratowe (Claim ze strony 11).
#[derive(Clone, Debug)]
pub struct Protocol25Constraints<F: Field> {
    pub linear_constraints: Vec<LinearConstraint<F>>,
    pub quad_constraint: QuadraticConstraint<F>,
    pub total_w_prime_len: usize,
}

impl<F: Field> Protocol25Constraints<F> {
    /// Buduje zestaw ograniczeń na podstawie parametrów protokołu:
    /// - `claim_y`: początkowa wartość sumy na danej warstwie ($Y_j$),
    /// - `challenges`: wektor wyzwań losowych $(r_0, \dots, r_{R-1})$,
    /// - `masked_transcript`: zamaskowany transkrypt $T'$ otrzymany od Provera,
    /// - `q_eval`: ewaluacja publicznego wielomianu połączeń $\tilde{Q}(r_{out}, L, R)$,
    /// - `witness_len`: długość oryginalnego wektora świadka $|w|$,
    /// - `v_in`: liczba zmiennych wejściowych dla warstwy (tzn. $R = 2 \cdot v_{in}$).
    pub fn build(
        claim_y: F,
        challenges: &[F],
        masked_transcript: &MaskedTranscript<F>,
        q_eval: F,
        witness_len: usize,
        v_in: usize,
    ) -> Self {
        let num_rounds = challenges.len();
        assert_eq!(
            num_rounds,
            masked_transcript.rounds.len(),
            "Liczba wyzwań musi odpowiadać liczbie rund w transkrypcie"
        );
        assert_eq!(
            num_rounds,
            2 * v_in,
            "Liczba rund sumchecka musi wynosić 2 * v_in"
        );

        // Rozmiar wektora masek to 3 * num_rounds + 2
        let pads_len = num_rounds * 3 + 2;
        let total_w_prime_len = witness_len + pads_len;

        let mut linear_constraints = Vec::new();

        // 1. Więz liniowy dla rundy 0: pad_{0,0} + pad_{0,1} = P_0(0) + P_0(1) - Y
        {
            let mut weights = vec![F::zero(); total_w_prime_len];
            let idx_p0 = witness_len;
            let idx_p1 = witness_len + 1;
            weights[idx_p0] = F::one();
            weights[idx_p1] = F::one();

            let target = masked_transcript.rounds[0].eval_0 + masked_transcript.rounds[0].eval_1 - claim_y;
            linear_constraints.push(LinearConstraint::new(weights, target));
        }

        // 2. Więzy liniowe dla kolejnych rund i = 0 .. num_rounds - 2:
        // pad_{i+1, 0} + pad_{i+1, 1} - <lambda_{r_i}, pad_i> = P_{i+1}(0) + P_{i+1}(1) - <lambda_{r_i}, P_i>
        for i in 0..(num_rounds - 1) {
            let r_i = challenges[i];
            let lambdas = lagrange_eval_degree2(r_i);

            let mut weights = vec![F::zero(); total_w_prime_len];

            // pad_{i+1, 0} oraz pad_{i+1, 1} z wagą +1
            let idx_next_0 = witness_len + (i + 1) * 3;
            let idx_next_1 = witness_len + (i + 1) * 3 + 1;
            weights[idx_next_0] = F::one();
            weights[idx_next_1] = F::one();

            // - <lambda_{r_i}, pad_i>
            let idx_cur_0 = witness_len + i * 3;
            let idx_cur_1 = witness_len + i * 3 + 1;
            let idx_cur_2 = witness_len + i * 3 + 2;
            weights[idx_cur_0] = -lambdas[0];
            weights[idx_cur_1] = -lambdas[1];
            weights[idx_cur_2] = -lambdas[2];

            let p_cur = &masked_transcript.rounds[i];
            let p_next = &masked_transcript.rounds[i + 1];

            let lambda_dot_p = lambdas[0] * p_cur.eval_0 + lambdas[1] * p_cur.eval_1 + lambdas[2] * p_cur.eval_2;
            let target = p_next.eval_0 + p_next.eval_1 - lambda_dot_p;

            linear_constraints.push(LinearConstraint::new(weights, target));
        }

        // 3. Więzy dopasowania multilinearnej ewaluacji wejść L i R:
        // w(L) + pad_L = W_L  => sum_k eq(L, k) * w[k] + pad_L = W_L
        // w(R) + pad_R = W_R  => sum_k eq(R, k) * w[k] + pad_R = W_R
        let l_challenges = &challenges[0..v_in];
        let r_challenges = &challenges[v_in..(2 * v_in)];

        let idx_pad_l = witness_len + num_rounds * 3;
        let idx_pad_r = witness_len + num_rounds * 3 + 1;

        // Ograniczenie dla W_L
        {
            let mut weights = vec![F::zero(); total_w_prime_len];
            for k in 0..witness_len {
                weights[k] = eq_eval(l_challenges, k);
            }
            weights[idx_pad_l] = F::one();
            linear_constraints.push(LinearConstraint::new(weights, masked_transcript.masked_w_l));
        }

        // Ograniczenie dla W_R
        {
            let mut weights = vec![F::zero(); total_w_prime_len];
            for k in 0..witness_len {
                weights[k] = eq_eval(r_challenges, k);
            }
            weights[idx_pad_r] = F::one();
            linear_constraints.push(LinearConstraint::new(weights, masked_transcript.masked_w_r));
        }

        // 4. Ograniczenie kwadratowe dla ostatniej rundy ell = num_rounds - 1
        let ell = num_rounds - 1;
        let r_ell = challenges[ell];
        let lambdas_ell = lagrange_eval_degree2(r_ell);

        let p_ell = &masked_transcript.rounds[ell];
        let w_l = masked_transcript.masked_w_l;
        let w_r = masked_transcript.masked_w_r;

        let lambda_dot_p_ell = lambdas_ell[0] * p_ell.eval_0 + lambdas_ell[1] * p_ell.eval_1 + lambdas_ell[2] * p_ell.eval_2;
        let quad_target = lambda_dot_p_ell - q_eval * w_l * w_r;

        let quad_constraint = QuadraticConstraint {
            idx_pad_ell_0: witness_len + ell * 3,
            idx_pad_ell_1: witness_len + ell * 3 + 1,
            idx_pad_ell_2: witness_len + ell * 3 + 2,
            idx_pad_l,
            idx_pad_r,
            coeff_pad_ell: lambdas_ell,
            coeff_pad_l: -q_eval * w_r,
            coeff_pad_r: -q_eval * w_l,
            coeff_quad: q_eval,
            target: quad_target,
        };

        Self {
            linear_constraints,
            quad_constraint,
            total_w_prime_len,
        }
    }

    /// Łączy wszystkie ograniczenia liniowe w pojedyncze losowe ograniczenie liniowe:
    /// $\mathbf{a}_{comb} = \sum_j \beta_j \mathbf{a}_j$, $b_{comb} = \sum_j \beta_j b_j$.
    /// Używane przez protokół Ligero do jednoetapowej weryfikacji wszystkich równości liniowych.
    pub fn combine_linear(&self, weights: &[F]) -> LinearConstraint<F> {
        assert_eq!(
            weights.len(),
            self.linear_constraints.len(),
            "Liczba wag musi odpowiadać liczbie ograniczeń liniowych"
        );

        let mut combined_weights = vec![F::zero(); self.total_w_prime_len];
        let mut combined_target = F::zero();

        for (constraint, &beta) in self.linear_constraints.iter().zip(weights.iter()) {
            combined_target += beta * constraint.target;
            for (w_out, &w_in) in combined_weights.iter_mut().zip(constraint.weights.iter()) {
                *w_out += beta * w_in;
            }
        }

        LinearConstraint::new(combined_weights, combined_target)
    }

    /// Sprawdza bezpośrednio, czy dany świadek $w' = (w, \mathbf{pad})$ spełnia WSZYSTKIE
    /// ograniczenia liniowe oraz ograniczenie kwadratowe.
    pub fn verify_all(&self, w_prime: &[F]) -> bool {
        if w_prime.len() != self.total_w_prime_len {
            return false;
        }

        for (_idx, c) in self.linear_constraints.iter().enumerate() {
            if !c.is_satisfied(w_prime) {
                #[cfg(test)]
                println!("Ograniczenie liniowe {} nie zostało spełnione!", _idx);
                return false;
            }
        }

        if !self.quad_constraint.is_satisfied(w_prime) {
            #[cfg(test)]
            println!("Ograniczenie kwadratowe nie zostało spełnione!");
            return false;
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::MontConfig;
    use ark_std::test_rng;
    use crate::circuit::gate::QuadGate;
    use crate::circuit::layered::CircuitLayer;
    use crate::protocol25::pad::{LayerPads, MaskedRoundPoly};
    use crate::sumcheck::prover::SumcheckProver;

    #[derive(MontConfig)]
    #[modulus = "17"]
    #[generator = "3"]
    pub struct FqConfig;
    pub type F17 = ark_ff::Fp64<ark_ff::MontBackend<FqConfig, 1>>;

    #[test]
    fn test_lagrange_interpolation_degree2() {
        let r = F17::from(5u64);
        let lambdas = lagrange_eval_degree2(r);

        // Wielomian g(X) = 2*X^2 + 3*X + 4
        // g(0) = 4
        // g(1) = 2 + 3 + 4 = 9
        // g(2) = 2*4 + 3*2 + 4 = 18 = 1 (mod 17)
        // g(5) = 2*25 + 3*5 + 4 = 50 + 15 + 4 = 69 = 1 (mod 17)
        let g0 = F17::from(4u64);
        let g1 = F17::from(9u64);
        let g2 = F17::from(1u64);

        let interpolated = lambdas[0] * g0 + lambdas[1] * g1 + lambdas[2] * g2;
        assert_eq!(interpolated, F17::from(1u64));
    }

    #[test]
    fn test_protocol25_honest_witness_satisfies_all_constraints() {
        let mut rng = test_rng();

        // 1. Tworzymy prostą warstwę obwodu: 1 zmienna wejściowa (v_in = 1, 2 druty: wire 0 = 1, wire 1 = witness)
        // Bramka: V_0[1] = V_1[1] * V_1[1] (kwadrat)
        let gates = vec![QuadGate::mul(1, 1, 1)];
        let layer = CircuitLayer::<F17>::new(0, 2, 2, gates);

        // Świadek: wire 0 = 1 (konwencja), wire 1 = 3
        let witness = vec![F17::from(1u64), F17::from(3u64)];
        let v_in = 1;
        let num_rounds = 2 * v_in; // 2 rundy (L i R)

        // Wyjście z warstwy: V_0[0] = 1, V_0[1] = 3 * 3 = 9
        let v_out = layer.evaluate(&witness);
        let r_out = vec![F17::from(2u64)];
        let claim_y = eq_eval(&r_out, 0) * v_out[0] + eq_eval(&r_out, 1) * v_out[1];

        // 2. Generujemy uczciwe wielomiany sumchecka
        let alpha = F17::from(1u64);
        let mut prover = SumcheckProver::new(layer.clone(), alpha, r_out.clone(), r_out.clone(), &witness);
        let poly_0 = prover.compute_round_poly();

        let r0 = F17::from(4u64);
        prover.receive_challenge(r0);
        let poly_1 = prover.compute_round_poly();

        let r1 = F17::from(6u64);
        prover.receive_challenge(r1);

        let challenges = vec![r0, r1];

        // 3. Losujemy maski OTP i tworzymy zamaskowany transkrypt
        let pads = LayerPads::<F17>::sample(num_rounds, &mut rng);

        let masked_p0 = MaskedRoundPoly::mask([poly_0.eval_0, poly_0.eval_1, poly_0.eval_2], pads.round_pads[0]);
        let masked_p1 = MaskedRoundPoly::mask([poly_1.eval_0, poly_1.eval_1, poly_1.eval_2], pads.round_pads[1]);

        let l_challenges = vec![r0];
        let r_challenges = vec![r1];
        let true_w_l = eq_eval(&l_challenges, 0) * witness[0] + eq_eval(&l_challenges, 1) * witness[1];
        let true_w_r = eq_eval(&r_challenges, 0) * witness[0] + eq_eval(&r_challenges, 1) * witness[1];

        let masked_transcript = MaskedTranscript {
            rounds: vec![masked_p0, masked_p1],
            masked_w_l: true_w_l + pads.pad_l,
            masked_w_r: true_w_r + pads.pad_r,
        };

        // 4. Budujemy wektor rozszerzony w' = (w, pads)
        let mut w_prime = witness.clone();
        w_prime.extend(pads.to_vec());

        // 5. Weryfikator buduje ograniczenia
        let q_eval = layer.eval_wiring_predicate(&r_out, &l_challenges, &r_challenges);
        let constraints = Protocol25Constraints::<F17>::build(
            claim_y,
            &challenges,
            &masked_transcript,
            q_eval,
            witness.len(),
            v_in,
        );

        // 6. Test: Uczciwy świadek spełnia WSZYSTKIE ograniczenia!
        assert!(constraints.verify_all(&w_prime), "Uczciwy świadek musi spełniać wszystkie ograniczenia Protokołu 2.5!");

        // 7. Test kompresji liniowej losowymi wagami
        let weights = vec![F17::from(7u64); constraints.linear_constraints.len()];
        let combined = constraints.combine_linear(&weights);
        assert!(combined.is_satisfied(&w_prime), "Kombinacja liniowa musi być spełniona!");

        // 8. Test fałszowania: zepsucie świadka
        let mut bad_w_prime = w_prime.clone();
        bad_w_prime[1] = F17::from(4u64); // zmiana wartości drutu wejściowego
        assert!(!constraints.verify_all(&bad_w_prime), "Sfałszowany świadek nie może spełnić ograniczeń!");
    }
}
