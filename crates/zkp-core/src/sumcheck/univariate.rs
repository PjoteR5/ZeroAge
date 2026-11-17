#[allow(unused_imports)]
use ark_ff::{Field, One, Zero};

/// Jednowymiarowy wielomian stopnia co najwyżej 2: g(X) = a*X^2 + b*X + c.
/// W protokole Sumcheck wielomian rundy jest reprezentowany przez ewaluacje w 3 punktach:
/// g(0), g(1) oraz g(2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnivariateDegree2<F: Field> {
    pub eval_0: F,
    pub eval_1: F,
    pub eval_2: F,
}

impl<F: Field> UnivariateDegree2<F> {
    pub fn new(eval_0: F, eval_1: F, eval_2: F) -> Self {
        Self {
            eval_0,
            eval_1,
            eval_2,
        }
    }

    /// Sprawdza warunek pierwszej części rundy Sumchecka:
    /// g(0) + g(1) == claim
    pub fn check_sum(&self, claim: &F) -> bool {
        (self.eval_0 + self.eval_1) == *claim
    }

    /// Oblicza wartość wielomianu g(r) w losowym punkcie r za pomocą interpolacji Lagrange'a:
    /// L_0(r) = (r - 1)(r - 2) / 2
    /// L_1(r) = -r(r - 2)
    /// L_2(r) = r(r - 1) / 2
    pub fn evaluate(&self, r: &F) -> F {
        let two = F::from(2u64);
        let inv_two = two.inverse().expect("Ciało musi mieć charakterystykę != 2");

        let r_val = *r;
        let r_minus_1 = r_val - F::one();
        let r_minus_2 = r_val - two;

        // Bazy Lagrange'a dla punktów {0, 1, 2}
        let l_0 = r_minus_1 * r_minus_2 * inv_two;
        let l_1 = -(r_val * r_minus_2);
        let l_2 = r_val * r_minus_1 * inv_two;

        self.eval_0 * l_0 + self.eval_1 * l_1 + self.eval_2 * l_2
    }
}

#[cfg(test)]
#[allow(non_local_definitions)]
mod tests {
    use super::*;
    use ark_ff::{Fp64, MontBackend, MontConfig};

    #[derive(MontConfig)]
    #[modulus = "17"]
    #[generator = "3"]
    pub struct FqConfig;
    pub type F17 = Fp64<MontBackend<FqConfig, 1>>;

    #[test]
    fn test_univariate_degree2_interpolation() {
        // g(X) = 2*X^2 + 3*X + 5 mod 17
        // g(0) = 5
        // g(1) = 2 + 3 + 5 = 10
        // g(2) = 2*4 + 3*2 + 5 = 8 + 6 + 5 = 19 mod 17 = 2
        let poly = UnivariateDegree2::<F17>::new(
            F17::from(5u64),
            F17::from(10u64),
            F17::from(2u64),
        );

        // Sumcheck claim: g(0) + g(1) = 5 + 10 = 15
        assert!(poly.check_sum(&F17::from(15u64)));
        assert!(!poly.check_sum(&F17::from(14u64)));

        // Weryfikacja bazowych punktów:
        assert_eq!(poly.evaluate(&F17::zero()), F17::from(5u64));
        assert_eq!(poly.evaluate(&F17::one()), F17::from(10u64));
        assert_eq!(poly.evaluate(&F17::from(2u64)), F17::from(2u64));

        // Ewaluacja w nowym punkcie X = 3:
        // g(3) = 2*9 + 3*3 + 5 = 18 + 9 + 5 = 32 mod 17 = 15
        assert_eq!(poly.evaluate(&F17::from(3u64)), F17::from(15u64));
    }
}
