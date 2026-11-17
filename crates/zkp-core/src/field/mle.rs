use ark_ff::Field;

/// Gęsta reprezentacja wielomianu wieloliniowego (Multilinear Extension - MLE).
/// Przechowuje 2^v ewaluacji na wierzchołkach hipersześcianu boolowskiego {0, 1}^v.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DenseMultilinearExtension<F: Field> {
    /// Liczba zmiennych v wielomianu
    pub num_vars: usize,
    /// 2^v ewaluacji wielomianu na wierzchołkach kostki
    pub evaluations: Vec<F>,
}

impl<F: Field> DenseMultilinearExtension<F> {
    /// Tworzy nowy wielomian wieloliniowy na podstawie liczby zmiennych i wektora ewaluacji.
    /// Wymaga, aby evaluations.len() == 2^num_vars.
    pub fn new(num_vars: usize, evaluations: Vec<F>) -> Self {
        assert_eq!(
            evaluations.len(),
            1 << num_vars,
            "Liczba ewaluacji ({}) musi wynosić 2^{} ({})",
            evaluations.len(),
            num_vars,
            1 << num_vars
        );
        Self {
            num_vars,
            evaluations,
        }
    }

    /// Tworzy wielomian wieloliniowy z wektora ewaluacji, automatycznie wyliczając num_vars.
    /// Długość wektora musi być potęgą dwójki.
    pub fn from_evaluations(evaluations: Vec<F>) -> Self {
        assert!(
            evaluations.len().is_power_of_two(),
            "Długość wektora ewaluacji musi być potęgą dwójki"
        );
        let num_vars = evaluations.len().trailing_zeros() as usize;
        Self {
            num_vars,
            evaluations,
        }
    }

    /// Zwraca liczbę zmiennych wielomianu.
    pub fn num_vars(&self) -> usize {
        self.num_vars
    }

    /// Zamraża pierwszą zmienną X_0, podstawiając pod nią wartość wyzwania `r`.
    /// Zwraca nowy wielomian o (num_vars - 1) zmiennych i o połowę krótszym wektorze ewaluacji.
    /// 
    /// Wzór interpolacji liniowej dla każdej pary:
    /// new_eval[i] = (1 - r) * eval[2i] + r * eval[2i + 1]
    ///             = eval[2i] + r * (eval[2i + 1] - eval[2i])
    pub fn bind(&self, r: &F) -> Self {
        assert!(self.num_vars > 0, "Nie można zamrozić wielomianu o 0 zmiennych");
        let half = self.evaluations.len() / 2;
        let mut new_evaluations = Vec::with_capacity(half);

        for i in 0..half {
            let left = self.evaluations[2 * i];
            let right = self.evaluations[2 * i + 1];
            // left + r * (right - left) to 1 mnożenie i 2 dodawania/odejmowania
            let val = left + *r * (right - left);
            new_evaluations.push(val);
        }

        Self {
            num_vars: self.num_vars - 1,
            evaluations: new_evaluations,
        }
    }

    /// Zamraża pierwszą zmienną w miejscu (in-place), redukując wektor o połowę bez alokacji.
    pub fn bind_inplace(&mut self, r: &F) {
        assert!(self.num_vars > 0, "Nie można zamrozić wielomianu o 0 zmiennych");
        let half = self.evaluations.len() / 2;
        for i in 0..half {
            let left = self.evaluations[2 * i];
            let right = self.evaluations[2 * i + 1];
            self.evaluations[i] = left + *r * (right - left);
        }
        self.evaluations.truncate(half);
        self.num_vars -= 1;
    }

    /// Oblicza wartość wielomianu P(r_0, r_1, ..., r_{v-1}) w losowym punkcie r.
    /// Złożoność czasowa: O(2^v) operacji ciała.
    pub fn evaluate(&self, point: &[F]) -> F {
        assert_eq!(
            point.len(),
            self.num_vars,
            "Punkt ewaluacji musi mieć wymiar równy num_vars ({})",
            self.num_vars
        );

        if self.num_vars == 0 {
            return self.evaluations[0];
        }

        // Kopiujemy ewaluacje i redukujemy je kolejno dla każdego r_i
        let mut current_evals = self.evaluations.clone();
        for r in point {
            let half = current_evals.len() / 2;
            for i in 0..half {
                let left = current_evals[2 * i];
                let right = current_evals[2 * i + 1];
                current_evals[i] = left + *r * (right - left);
            }
            current_evals.truncate(half);
        }

        current_evals[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{Fp64, MontBackend, MontConfig, One, Zero};

    #[derive(MontConfig)]
    #[modulus = "17"]
    #[generator = "3"]
    pub struct FqConfig;
    pub type F17 = Fp64<MontBackend<FqConfig, 1>>;

    #[test]
    fn test_mle_single_variable() {
        // P(X): P(0) = 3, P(1) = 7  =>  P(X) = 3 + 4X (mod 17)
        let mle = DenseMultilinearExtension::<F17>::new(
            1,
            vec![F17::from(3u64), F17::from(7u64)],
        );

        // P(0) = 3
        assert_eq!(mle.evaluate(&[F17::zero()]), F17::from(3u64));
        // P(1) = 7
        assert_eq!(mle.evaluate(&[F17::one()]), F17::from(7u64));
        // P(2) = 3 + 4*2 = 11
        assert_eq!(mle.evaluate(&[F17::from(2u64)]), F17::from(11u64));
    }

    #[test]
    fn test_mle_two_variables_bind() {
        // P(X0, X1) w konwencji little-endian (indeks = b0 + 2*b1):
        // indeks 0 (X0=0, X1=0) -> 1
        // indeks 1 (X0=1, X1=0) -> 2
        // indeks 2 (X0=0, X1=1) -> 3
        // indeks 3 (X0=1, X1=1) -> 8
        let mle = DenseMultilinearExtension::<F17>::new(
            2,
            vec![
                F17::from(1u64), // (0, 0)
                F17::from(2u64), // (1, 0)
                F17::from(3u64), // (0, 1)
                F17::from(8u64), // (1, 1)
            ],
        );

        // Weryfikacja wierzchołków hipersześcianu
        assert_eq!(mle.evaluate(&[F17::from(0u64), F17::from(0u64)]), F17::from(1u64));
        assert_eq!(mle.evaluate(&[F17::from(1u64), F17::from(0u64)]), F17::from(2u64));
        assert_eq!(mle.evaluate(&[F17::from(0u64), F17::from(1u64)]), F17::from(3u64));
        assert_eq!(mle.evaluate(&[F17::from(1u64), F17::from(1u64)]), F17::from(8u64));

        // Test operacji bind: zamrażamy X0 = 2
        // Dla X1=0 (para z indeksów 0 i 1): 1 + 2*(2 - 1) = 3
        // Dla X1=1 (para z indeksów 2 i 3): 3 + 2*(8 - 3) = 13
        let bound = mle.bind(&F17::from(2u64));
        assert_eq!(bound.num_vars(), 1);
        assert_eq!(bound.evaluate(&[F17::from(0u64)]), F17::from(3u64));
        assert_eq!(bound.evaluate(&[F17::from(1u64)]), F17::from(13u64));

        // Ewaluacja w punkcie (X0=2, X1=3):
        // P(2, 3) = 3 + 3*(13 - 3) = 33 = 16 mod 17
        assert_eq!(mle.evaluate(&[F17::from(2u64), F17::from(3u64)]), F17::from(16u64));
        assert_eq!(bound.evaluate(&[F17::from(3u64)]), F17::from(16u64));
    }
}
