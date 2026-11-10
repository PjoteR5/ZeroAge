#[allow(unused_imports)]
use ark_ff::{Field, One, Zero};
use crate::circuit::layered::CircuitLayer;
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

        // Uzupełniamy przewody zerami do potęgi 2
        let mut padded_v = v_in_wires.to_vec();
        padded_v.resize(1 << omega_in, F::zero());
        let v_in_mle = DenseMultilinearExtension::new(omega_in, padded_v);

        Self {
            layer,
            alpha,
            r_out_0,
            r_out_1,
            v_in_mle,
            omega_in,
            fixed_challenges: Vec::with_capacity(2 * omega_in),
        }
    }

    /// Całkowita liczba rund sumchecka dla tej warstwy: 2 * omega_in (dla L i R)
    pub fn total_rounds(&self) -> usize {
        2 * self.omega_in
    }

    /// Wylicza jednowymiarowy wielomian stopnia 2 g_k(X) dla aktualnej rundy k.
    /// Wartości liczone są dla X in {0, 1, 2}.
    pub fn compute_round_poly(&self) -> UnivariateDegree2<F> {
        let k = self.fixed_challenges.len();
        let total = self.total_rounds();
        assert!(k < total, "Wszystkie rundy zostały już ukończone");

        let remaining = total - k - 1;
        let num_combinations = 1 << remaining;

        let mut eval_0 = F::zero();
        let mut eval_1 = F::zero();
        let mut eval_2 = F::zero();

        // Iterujemy po wszystkich wierzchołkach hipersześcianu pozostałych wolnych zmiennych
        for b in 0..num_combinations {
            for x_val in 0..=2 {
                let x_f = F::from(x_val as u64);

                // Składamy pełny punkt (L, R) o długości 2 * omega_in
                let mut full_point = self.fixed_challenges.clone();
                full_point.push(x_f);

                // Dopisujemy bity z b
                for bit_idx in 0..remaining {
                    let bit = (b >> bit_idx) & 1;
                    full_point.push(if bit == 1 { F::one() } else { F::zero() });
                }

                // Dzielimy na L i R
                let l_point = &full_point[0..self.omega_in];
                let r_point = &full_point[self.omega_in..2 * self.omega_in];

                // Obliczamy składniki:
                // 1. Q_term = alpha * Q(r_out_0, L, R) + (1 - alpha) * Q(r_out_1, L, R)
                let q0 = self.layer.eval_wiring_predicate(&self.r_out_0, l_point, r_point);
                let q1 = self.layer.eval_wiring_predicate(&self.r_out_1, l_point, r_point);
                let q_term = self.alpha * q0 + (F::one() - self.alpha) * q1;

                // 2. V_term = V_in(L) * V_in(R)
                let v_l = self.v_in_mle.evaluate(l_point);
                let v_r = self.v_in_mle.evaluate(r_point);

                let term_val = q_term * v_l * v_r;

                match x_val {
                    0 => eval_0 += term_val,
                    1 => eval_1 += term_val,
                    2 => eval_2 += term_val,
                    _ => unreachable!(),
                }
            }
        }

        UnivariateDegree2::new(eval_0, eval_1, eval_2)
    }

    /// Odbiera wyzwanie losowe r_k od weryfikatora i przechodzi do kolejnej rundy.
    pub fn receive_challenge(&mut self, challenge: F) {
        self.fixed_challenges.push(challenge);
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
