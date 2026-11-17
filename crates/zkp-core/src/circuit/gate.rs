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

    /// Bramka bitowego AND: V_j[out] = a * b dla a, b in {0, 1}.
    pub fn and_bit(out_wire: usize, a: usize, b: usize) -> Self {
        Self::mul(out_wire, a, b)
    }

    /// Bramka bitowego NOT: V_j[out] = 1 - a dla a in {0, 1}.
    pub fn not_bit(out_wire: usize, a: usize) -> Self {
        Self::new(
            out_wire,
            vec![
                QuadTerm::constant(F::one()),
                QuadTerm::linear(a, -F::one()),
            ],
        )
    }

    /// Bramka bitowego XOR w ciele F_p: V_j[out] = a + b - 2*a*b dla a, b in {0, 1}.
    pub fn xor_bit(out_wire: usize, a: usize, b: usize) -> Self {
        let two = F::one() + F::one();
        Self::new(
            out_wire,
            vec![
                QuadTerm::linear(a, F::one()),
                QuadTerm::linear(b, F::one()),
                QuadTerm::new(a, b, -two),
            ],
        )
    }

    /// Algebraiczna bramka SHA-256 `Ch(x, y, z) = (x & y) ^ (!x & z)` w jednej warstwie kwadratowej:
    /// Dla bitów x, y, z in {0, 1}: Ch(x, y, z) = z + x * (y - z) = z + x*y - x*z.
    pub fn sha256_ch_bit(out_wire: usize, x: usize, y: usize, z: usize) -> Self {
        Self::new(
            out_wire,
            vec![
                QuadTerm::linear(z, F::one()),
                QuadTerm::new(x, y, F::one()),
                QuadTerm::new(x, z, -F::one()),
            ],
        )
    }

    /// Algebraiczna bramka SHA-256 `Maj(x, y, z) = (x & y) ^ (x & z) ^ (y & z)` z wykorzystaniem
    /// pomocniczego przewodu `xy_wire = x * y`:
    /// Maj(x, y, z) = xy + x*z + y*z - 2*xy*z (stopień <= 2 względem (x, y, z, xy)).
    pub fn sha256_maj_from_xy(
        out_wire: usize,
        x: usize,
        y: usize,
        z: usize,
        xy_wire: usize,
    ) -> Self {
        let two = F::one() + F::one();
        Self::new(
            out_wire,
            vec![
                QuadTerm::linear(xy_wire, F::one()),
                QuadTerm::new(x, z, F::one()),
                QuadTerm::new(y, z, F::one()),
                QuadTerm::new(xy_wire, z, -two),
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

    #[test]
    fn test_sha256_boolean_gates_truth_table() {
        for bx in 0..=1u64 {
            for by in 0..=1u64 {
                for bz in 0..=1u64 {
                    let bxy = bx & by;
                    // V[0]=1, V[1]=x, V[2]=y, V[3]=z, V[4]=x*y
                    let wires = vec![
                        F17::one(),
                        F17::from(bx),
                        F17::from(by),
                        F17::from(bz),
                        F17::from(bxy),
                    ];

                    let xor_g = QuadGate::<F17>::xor_bit(1, 1, 2);
                    assert_eq!(xor_g.evaluate(&wires), F17::from(bx ^ by));

                    let ch_g = QuadGate::<F17>::sha256_ch_bit(2, 1, 2, 3);
                    let expected_ch = (bx & by) ^ ((!bx & 1) & bz);
                    assert_eq!(ch_g.evaluate(&wires), F17::from(expected_ch));

                    let maj_g = QuadGate::<F17>::sha256_maj_from_xy(3, 1, 2, 3, 4);
                    let expected_maj = (bx & by) ^ (bx & bz) ^ (by & bz);
                    assert_eq!(maj_g.evaluate(&wires), F17::from(expected_maj));
                }
            }
        }
    }
}
