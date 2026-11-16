#[allow(unused_imports)]
use ark_ff::{Field, One, Zero};

/// Pojedynczy składnik formy kwadratowej: coeff * V_{j+1}[left] * V_{j+1}[right].
/// Zgodnie z konwencją V_{j+1}[0] = 1, co pozwala na reprezentację:
/// - stałych:      coeff * V[0] * V[0] = coeff * 1 * 1 = coeff
/// - wyrazów lin.: coeff * V[left] * V[0] = coeff * V[left] * 1
/// - iloczynów:    coeff * V[left] * V[right]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuadTerm<F: Field> {
    pub left: usize,
    pub right: usize,
    pub coeff: F,
}

impl<F: Field> QuadTerm<F> {
    pub fn new(left: usize, right: usize, coeff: F) -> Self {
        Self { left, right, coeff }
    }

    /// Iloczyn dwóch przewodów: 1 * V[left] * V[right]
    pub fn mul(left: usize, right: usize) -> Self {
        Self {
            left,
            right,
            coeff: F::one(),
        }
    }

    /// Wyraz liniowy: coeff * V[wire] * 1
    pub fn linear(wire: usize, coeff: F) -> Self {
        Self {
            left: wire,
            right: 0,
            coeff,
        }
    }

    /// Wyraz stały: coeff * 1 * 1
    pub fn constant(coeff: F) -> Self {
        Self {
            left: 0,
            right: 0,
            coeff,
        }
    }

    /// Ewaluuje wartość składnika na podstawie wektora wartości przewodów wejściowych
    pub fn evaluate(&self, in_wires: &[F]) -> F {
        self.coeff * in_wires[self.left] * in_wires[self.right]
    }
}

/// Bramka kwadratowa stopnia 2 (Quad Gate) dla wyjściowego przewodu out_wire:
/// V_j[out_wire] = sum_{terms} coeff * V_{j+1}[left] * V_{j+1}[right]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuadGate<F: Field> {
    pub out_wire: usize,
    pub terms: Vec<QuadTerm<F>>,
}

impl<F: Field> QuadGate<F> {
    pub fn new(out_wire: usize, terms: Vec<QuadTerm<F>>) -> Self {
        Self { out_wire, terms }
    }

    /// Oblicza wartość przewodu wyjściowego na podstawie wartości warstwy wejściowej
    pub fn evaluate(&self, in_wires: &[F]) -> F {
        let mut sum = F::zero();
        for term in &self.terms {
            sum += term.evaluate(in_wires);
        }
        sum
    }

    // --- FABRYKI WYGODNYCH BRAMEK STANDARDOWYCH ---

    /// Bramka dodawania: V_j[out] = V_{j+1}[a] + V_{j+1}[b]
    pub fn add(out_wire: usize, a: usize, b: usize) -> Self {
        Self::new(
            out_wire,
            vec![
                QuadTerm::linear(a, F::one()),
                QuadTerm::linear(b, F::one()),
            ],
        )
    }

    /// Bramka odejmowania: V_j[out] = V_{j+1}[a] - V_{j+1}[b]
    pub fn sub(out_wire: usize, a: usize, b: usize) -> Self {
        Self::new(
            out_wire,
            vec![
                QuadTerm::linear(a, F::one()),
                QuadTerm::linear(b, -F::one()),
            ],
        )
    }

    /// Bramka mnożenia: V_j[out] = V_{j+1}[a] * V_{j+1}[b]
    pub fn mul(out_wire: usize, a: usize, b: usize) -> Self {
        Self::new(out_wire, vec![QuadTerm::mul(a, b)])
    }

    /// Bramka stałej: V_j[out] = c
    pub fn constant(out_wire: usize, c: F) -> Self {
        Self::new(out_wire, vec![QuadTerm::constant(c)])
    }

    /// Bramka skalowania: V_j[out] = c * V_{j+1}[a]
    pub fn scale(out_wire: usize, a: usize, c: F) -> Self {
        Self::new(out_wire, vec![QuadTerm::linear(a, c)])
    }

    /// Sprawdzenie równości dwóch przewodów: V_j[out] = V_{j+1}[a] - V_{j+1}[b]
    /// Jeśli a == b, to wyjście wynosi 0 (spełnienie obwodu ZK).
    pub fn assert_equal(out_wire: usize, a: usize, b: usize) -> Self {
        Self::sub(out_wire, a, b)
    }

    /// Więz binarności: V_j[out] = V_{j+1}[a]^2 - V_{j+1}[a]
    /// Wyjście wynosi 0 wtedy i tylko wtedy, gdy V_{j+1}[a] in {0, 1}.
    pub fn assert_bit(out_wire: usize, a: usize) -> Self {
        Self::new(
            out_wire,
            vec![
                QuadTerm::mul(a, a),           // a * a
                QuadTerm::linear(a, -F::one()), // -a
            ],
        )
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
    fn test_quad_gate_arithmetic() {
        // in_wires: V[0]=1 (stała), V[1]=5, V[2]=7
        let in_wires = vec![F17::one(), F17::from(5u64), F17::from(7u64)];

        // 1. Dodawanie: 5 + 7 = 12
        let add_gate = QuadGate::<F17>::add(1, 1, 2);
        assert_eq!(add_gate.evaluate(&in_wires), F17::from(12u64));

        // 2. Mnożenie: 5 * 7 = 35 mod 17 = 1
        let mul_gate = QuadGate::<F17>::mul(2, 1, 2);
        assert_eq!(mul_gate.evaluate(&in_wires), F17::from(1u64));

        // 3. Odejmowanie: 5 - 7 = -2 mod 17 = 15
        let sub_gate = QuadGate::<F17>::sub(3, 1, 2);
        assert_eq!(sub_gate.evaluate(&in_wires), F17::from(15u64));

        // 4. Test więzu binarnego dla bitu 1: 1^2 - 1 = 0
        let bit_gate = QuadGate::<F17>::assert_bit(4, 0); // V[0]=1
        assert_eq!(bit_gate.evaluate(&in_wires), F17::zero());

        // Test więzu binarnego dla liczby 5 (nie jest bitem): 5^2 - 5 = 20 mod 17 = 3 != 0
        let non_bit_gate = QuadGate::<F17>::assert_bit(5, 1); // V[1]=5
        assert_eq!(non_bit_gate.evaluate(&in_wires), F17::from(3u64));
    }
}
