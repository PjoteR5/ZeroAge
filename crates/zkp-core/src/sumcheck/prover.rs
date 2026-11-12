#[allow(unused_imports)]
use ark_ff::{Field, One, Zero};
use crate::circuit::layered::{build_eq_table, eq_eval, CircuitLayer};
use crate::field::mle::DenseMultilinearExtension;
use crate::sumcheck::univariate::UnivariateDegree2;

/// Prover protokołu Sumcheck dla pojedynczej warstwy obwodu (Rozdział 2.1, Protokół 2.2).
pub struct SumcheckProver<F: Field> {
    pub layer: CircuitLayer<F>,
    pub alpha: F,
    pub r_out_0: Vec<F>,
    pub r_out_1: Vec<F>,
    /// Wielomian MLE wartości przewodów wejściowych V_{j+1}
    pub v_in_mle: DenseMultilinearExtension<F>,
    pub omega_in: usize,
    /// Aktualnie ustalone wyzwania w rundach: najpierw L_0..L_{omega-1}, potem R_0..R_{omega-1}
    pub fixed_challenges: Vec<F>,
    /// Prekomputowany czynnik wyjściowy dla stałego przewodu 0
    q_wire0: F,
    /// Prekomputowane czynniki wyjściowe dla każdej bramki w warstwie
    gate_q: Vec<F>,
    /// Bieżąco zwinięty wektor wag po zmiennych L (pierwsza połowa) lub R (druga połowa)
    weight_bound: DenseMultilinearExtension<F>,
    /// Bieżąco zwinięty MLE wartości przewodów wejściowych V_in
    v_bound_current: DenseMultilinearExtension<F>,
    /// Zapisana wartość V_in(L) po zakończeniu pierwszych omega_in rund
    v_l_cached: Option<F>,
}

impl<F: Field> SumcheckProver<F> {
    pub fn new(
        layer: CircuitLayer<F>,
        alpha: F,
        r_out_0: Vec<F>,
        r_out_1: Vec<F>,
        v_in_wires: &[F],
    ) -> Self {
        // Obliczamy liczbę zmiennych omega_in = ceil(log2(in_width))
        let in_width = layer.in_width;
        let mut next_pow2 = in_width.next_power_of_two();
        if next_pow2 < 2 {
            next_pow2 = 2;
        }
        let omega_in = next_pow2.trailing_zeros() as usize;
        let n_in = 1 << omega_in;

        // Uzupełniamy przewody zerami do potęgi 2
        let mut padded_v = v_in_wires.to_vec();
        padded_v.resize(n_in, F::zero());
        let v_in_mle = DenseMultilinearExtension::new(omega_in, padded_v);

        let one_minus_alpha = F::one() - alpha;
        let (q_wire0, gate_q) = if r_out_0.len() <= 20 && r_out_1.len() <= 20 {
            let eq_r0 = build_eq_table(&r_out_0);
            let eq_r1 = build_eq_table(&r_out_1);
            let mask0 = eq_r0.len() - 1;
            let mask1 = eq_r1.len() - 1;

            let qw0 = alpha * eq_r0[0] + one_minus_alpha * eq_r1[0];
            let gq = layer
                .gates
                .iter()
                .map(|g| {
                    alpha * eq_r0[g.out_wire & mask0] + one_minus_alpha * eq_r1[g.out_wire & mask1]
                })
                .collect::<Vec<_>>();
            (qw0, gq)
        } else {
            let qw0 = alpha * eq_eval(&r_out_0, 0) + one_minus_alpha * eq_eval(&r_out_1, 0);
            let gq = layer
                .gates
                .iter()
                .map(|g| {
                    alpha * eq_eval(&r_out_0, g.out_wire)
                        + one_minus_alpha * eq_eval(&r_out_1, g.out_wire)
                })
                .collect::<Vec<_>>();
            (qw0, gq)
        };

        // Prekomputujemy początkową tablicę wag dla lewych wejść:
        // weight_by_left[left] = sum_{(out, right, coeff)} q(out) * coeff * V_in[right]
        let mut weights = vec![F::zero(); n_in];
        weights[0] = q_wire0 * v_in_mle.evaluations[0];
        for (gate, &q_out) in layer.gates.iter().zip(gate_q.iter()) {
            if q_out.is_zero() {
                continue;
            }
            for t in &gate.terms {
                if t.left < n_in && t.right < n_in {
                    let v_right = v_in_mle.evaluations[t.right];
                    if !v_right.is_zero() {
                        weights[t.left] += q_out * t.coeff * v_right;
                    }
                }
            }
        }

        let weight_bound = DenseMultilinearExtension::new(omega_in, weights);
        let v_bound_current = v_in_mle.clone();

        Self {
            layer,
            alpha,
            r_out_0,
            r_out_1,
            v_in_mle,
            omega_in,
            fixed_challenges: Vec::with_capacity(2 * omega_in),
            q_wire0,
            gate_q,
            weight_bound,
            v_bound_current,
            v_l_cached: None,
        }
    }

    /// Całkowita liczba rund sumchecka dla tej warstwy: 2 * omega_in (dla L i R)
    pub fn total_rounds(&self) -> usize {
        2 * self.omega_in
    }

    /// Szybka metoda wyliczania wielomianu rundy g_k(X) w czasie O(|Gates| + |V|),
    /// zgodna z algorytmem Thalera (2013) oraz Rozdziałem 2.1 z artykułu Frigo & shelat.
    pub fn compute_round_poly_fast(&self) -> UnivariateDegree2<F> {
        let k = self.fixed_challenges.len();
        let total = self.total_rounds();
        assert!(k < total, "Wszystkie rundy zostały już ukończone");

        let scalar = if k < self.omega_in {
            F::one()
        } else {
            let v_l = self.v_l_cached.expect("Brak wartości V_in(L) dla połówki R");
            if v_l.is_zero() {
                return UnivariateDegree2::new(F::zero(), F::zero(), F::zero());
            }
            v_l
        };

        let w_evals = &self.weight_bound.evaluations;
        let v_evals = &self.v_bound_current.evaluations;
        let half = w_evals.len() / 2;
        let two = F::one() + F::one();

        let mut eval_0 = F::zero();
        let mut eval_1 = F::zero();
        let mut eval_2 = F::zero();

        for i in 0..half {
            let w0 = w_evals[2 * i];
            let w1 = w_evals[2 * i + 1];
            let v0 = v_evals[2 * i];
            let v1 = v_evals[2 * i + 1];

            eval_0 += w0 * v0;
            eval_1 += w1 * v1;
            let w2 = two * w1 - w0;
            let v2 = two * v1 - v0;
            eval_2 += w2 * v2;
        }

        if k >= self.omega_in {
            eval_0 *= scalar;
            eval_1 *= scalar;
            eval_2 *= scalar;
        }

        UnivariateDegree2::new(eval_0, eval_1, eval_2)
    }

    /// Wylicza jednowymiarowy wielomian stopnia 2 g_k(X) dla aktualnej rundy k.
    pub fn compute_round_poly(&self) -> UnivariateDegree2<F> {
        self.compute_round_poly_fast()
    }

    /// Odbiera wyzwanie losowe r_k od weryfikatora i przechodzi do kolejnej rundy.
    pub fn receive_challenge(&mut self, challenge: F) {
        let k = self.fixed_challenges.len();
        assert!(k < self.total_rounds(), "Wszystkie rundy zostały już ukończone");
        self.fixed_challenges.push(challenge);

        self.v_bound_current.bind_inplace(&challenge);
        self.weight_bound.bind_inplace(&challenge);

        // Po zakończeniu ostatniej rundy L (k + 1 == omega_in) inicjujemy tablicę wag dla połówki R
        if k + 1 == self.omega_in {
            let v_l = self.v_bound_current.evaluations[0];
            self.v_l_cached = Some(v_l);
            self.v_bound_current = self.v_in_mle.clone();

            let n_in = self.v_in_mle.evaluations.len();
            let mut weights_r = vec![F::zero(); n_in];
            if !v_l.is_zero() {
                let eq_l = build_eq_table(&self.fixed_challenges[0..self.omega_in]);
                weights_r[0] = self.q_wire0 * eq_l[0];
                for (gate, &q_out) in self.layer.gates.iter().zip(self.gate_q.iter()) {
                    if q_out.is_zero() {
                        continue;
                    }
                    for t in &gate.terms {
                        if t.left < n_in && t.right < n_in {
                            let eq_left = eq_l[t.left];
                            if !eq_left.is_zero() {
                                weights_r[t.right] += q_out * t.coeff * eq_left;
                            }
                        }
                    }
                }
            }
            self.weight_bound = DenseMultilinearExtension::new(self.omega_in, weights_r);
        }
    }

    /// Po ukończeniu wszystkich rund zwraca ustalone losowe punkty (L, R).
    pub fn get_final_points(&self) -> (Vec<F>, Vec<F>) {
        assert_eq!(
            self.fixed_challenges.len(),
            self.total_rounds(),
            "Protokół sumcheck jeszcze się nie zakończył"
        );
        let l = self.fixed_challenges[0..self.omega_in].to_vec();
        let r = self.fixed_challenges[self.omega_in..2 * self.omega_in].to_vec();
        (l, r)
    }

    /// Oblicza roszczenia c_{j+1, 0} = V_{j+1}(L) oraz c_{j+1, 1} = V_{j+1}(R)
    pub fn compute_next_claims(&self) -> (F, F) {
        let (l, r) = self.get_final_points();
        (self.v_in_mle.evaluate(&l), self.v_in_mle.evaluate(&r))
    }
}
