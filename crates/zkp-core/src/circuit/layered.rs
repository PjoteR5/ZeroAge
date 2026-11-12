#[allow(unused_imports)]
use ark_ff::{Field, One, Zero};
use crate::circuit::gate::QuadGate;

/// Pomocnicza funkcja licząca wieloliniowy wielomian równości:
/// eq(x, y) = prod_{k} (x_k * y_k + (1 - x_k) * (1 - y_k))
/// Jeśli x == y na kostce boolowskiej, zwraca 1, w przeciwnym razie 0.
pub fn eq_eval<F: Field>(x: &[F], y_index: usize) -> F {
    let mut res = F::one();
    for (k, x_k) in x.iter().enumerate() {
        let bit = (y_index >> k) & 1;
        if bit == 1 {
            res *= *x_k;
        } else {
            res *= F::one() - *x_k;
        }
    }
    res
}

/// Buduje w czasie O(2^{x.len()}) tablicę wartości eq(x, y) dla wszystkich y in [0, 2^{x.len()}).
pub fn build_eq_table<F: Field>(x: &[F]) -> Vec<F> {
    let mut table = vec![F::zero(); 1 << x.len()];
    table[0] = F::one();
    for (k, &x_k) in x.iter().enumerate() {
        let one_minus = F::one() - x_k;
        let half = 1 << k;
        for i in 0..half {
            let val = table[i];
            table[i + half] = val * x_k;
            table[i] = val * one_minus;
        }
    }
    table
}

/// Pojedyncza warstwa obwodu j łącząca wejścia z warstwy (j+1) z wyjściami warstwy j.
#[derive(Clone, Debug)]
pub struct CircuitLayer<F: Field> {
    pub layer_id: usize,
    /// Liczba przewodów wejściowych (szerokość warstwy j+1)
    pub in_width: usize,
    /// Liczba przewodów wyjściowych (szerokość warstwy j)
    pub out_width: usize,
    /// Bramki kwadratowe dla przewodów wyjściowych 1..out_width (przewód 0 to zawsze stała 1)
    pub gates: Vec<QuadGate<F>>,
}

impl<F: Field> CircuitLayer<F> {
    pub fn new(layer_id: usize, in_width: usize, out_width: usize, gates: Vec<QuadGate<F>>) -> Self {
        Self {
            layer_id,
            in_width,
            out_width,
            gates,
        }
    }

    /// Wykonuje forward-pass warstwy: mając wartości przewodów V_{j+1}, oblicza V_j.
    pub fn evaluate(&self, in_wires: &[F]) -> Vec<F> {
        assert_eq!(
            in_wires.len(),
            self.in_width,
            "Niezgodna szerokość wejść do warstwy {}",
            self.layer_id
        );

        let mut out = vec![F::zero(); self.out_width];
        // Konwencja ZKP.pdf: przewód V_j[0] = 1
        out[0] = F::one();

        for gate in &self.gates {
            assert!(
                gate.out_wire < self.out_width,
                "Bramka odwołuje się do nieistniejącego przewodu wyjściowego {}",
                gate.out_wire
            );
            out[gate.out_wire] = gate.evaluate(in_wires);
        }

        out
    }

    /// Oblicza ewaluację rzadkiego wielomianu wieloliniowego okablowania \tilde{Q}_j(r_out, L, R)
    /// zgodnie z rozdziałem 2.1 ZKP.pdf:
    /// \tilde{Q}_j(r_out, L, R) = sum_{gates} eq(r_out, out_wire) * sum_{terms} coeff * eq(L, left) * eq(R, right)
    pub fn eval_wiring_predicate(&self, r_out: &[F], left_point: &[F], right_point: &[F]) -> F {
        if r_out.len() <= 20 && left_point.len() <= 20 && right_point.len() <= 20 {
            let eq_out_tbl = build_eq_table(r_out);
            let eq_l_tbl = build_eq_table(left_point);
            let eq_r_tbl = build_eq_table(right_point);
            let mask_out = eq_out_tbl.len() - 1;
            let mask_l = eq_l_tbl.len() - 1;
            let mask_r = eq_r_tbl.len() - 1;

            // Konwencja ZKP.pdf: przewód 0 na każdym poziomie to stała 1:
            // V_j[0] = 1 * V_{j+1}[0] * V_{j+1}[0], czyli składnik Q_j[0, 0, 0] = 1
            let mut total = eq_out_tbl[0] * eq_l_tbl[0] * eq_r_tbl[0];

            for gate in &self.gates {
                let eq_out = eq_out_tbl[gate.out_wire & mask_out];
                if eq_out.is_zero() {
                    continue;
                }

                let mut gate_sum = F::zero();
                for term in &gate.terms {
                    gate_sum += term.coeff
                        * eq_l_tbl[term.left & mask_l]
                        * eq_r_tbl[term.right & mask_r];
                }

                total += eq_out * gate_sum;
            }

            return total;
        }

        // Fallback dla wyjątkowo dużych wymiarów (> 2^20)
        let mut total = eq_eval(r_out, 0) * eq_eval(left_point, 0) * eq_eval(right_point, 0);

        for gate in &self.gates {
            let eq_out = eq_eval(r_out, gate.out_wire);
            if eq_out.is_zero() {
                continue;
            }

            let mut gate_sum = F::zero();
            for term in &gate.terms {
                let eq_l = eq_eval(left_point, term.left);
                let eq_r = eq_eval(right_point, term.right);
                gate_sum += term.coeff * eq_l * eq_r;
            }

            total += eq_out * gate_sum;
        }

        total
    }
}

/// Pełny warstwowy obwód arytmetyczny C.
/// Warstwy są indeksowane od 0 (wyjście) do d-1. Wejścia do obwodu stanowią warstwę d.
#[derive(Clone, Debug)]
pub struct LayeredCircuit<F: Field> {
    /// Warstwy obwodu: layers[0] to wyjście (warstwa 0), layers[d-1] to pierwsza warstwa nad wejściami
    pub layers: Vec<CircuitLayer<F>>,
    /// Szerokość warstwy wejściowej d (świadek + wejścia publiczne)
    pub input_width: usize,
}

impl<F: Field> LayeredCircuit<F> {
    pub fn new(layers: Vec<CircuitLayer<F>>, input_width: usize) -> Self {
        // Weryfikacja spójności wymiarów sąsiadujących warstw
        for i in 0..layers.len() - 1 {
            assert_eq!(
                layers[i].in_width,
                layers[i + 1].out_width,
                "Niezgodność szerokości między warstwą {} a {}",
                i,
                i + 1
            );
        }
        if let Some(last_layer) = layers.last() {
            assert_eq!(
                last_layer.in_width, input_width,
                "Wejście ostatniej warstwy musi pasować do input_width obwodu"
            );
        }

        Self {
            layers,
            input_width,
        }
    }

    /// Zwraca głębokość obwodu d (liczbę warstw).
    pub fn depth(&self) -> usize {
        self.layers.len()
    }

    /// Oblicza wartości wszystkich przewodów w całym obwodzie (od wejścia d do wyjścia 0).
    /// Zwraca wektor [V_0, V_1, ..., V_d].
    pub fn evaluate_all(&self, inputs: &[F]) -> Vec<Vec<F>> {
        assert_eq!(
            inputs.len(),
            self.input_width,
            "Liczba wejść musi być równa input_width ({})",
            self.input_width
        );

        let d = self.depth();
        let mut wire_values = vec![Vec::new(); d + 1];

        // Warstwa wejściowa d
        let mut v_d = inputs.to_vec();
        v_d[0] = F::one(); // V_d[0] = 1
        wire_values[d] = v_d;

        // Propagacja od warstwy d-1 w dół do 0
        for j in (0..d).rev() {
            let next_wires = self.layers[j].evaluate(&wire_values[j + 1]);
            wire_values[j] = next_wires;
        }

        wire_values
    }

    /// Sprawdza, czy wejście spełnia obwód ZK (zgodnie z ZKP.pdf: V_0[i] == 0 dla wszystkich i >= 1).
    pub fn is_satisfied(&self, inputs: &[F]) -> bool {
        let wire_values = self.evaluate_all(inputs);
        let v0 = &wire_values[0];

        // Wszystkie wyjścia poza indeksem 0 muszą być zerem
        for (_i, val) in v0.iter().enumerate().skip(1) {
            if !val.is_zero() {
                return false;
            }
        }
        true
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
    fn test_simple_layered_circuit() {
        // Budujemy obwód sprawdzający: czy (x + y) * z == 24 mod 17 (= 7)?
        //
        // Warstwa wejściowa d=2 (szerokość 4):
        // V_2[0] = 1 (stała)
        // V_2[1] = x = 3
        // V_2[2] = y = 5
        // V_2[3] = z = 3
        //
        // Warstwa pośrednia j=1 (szerokość 3):
        // V_1[0] = 1
        // V_1[1] = V_2[1] + V_2[2] (x + y = 3 + 5 = 8)
        // V_1[2] = V_2[3] * 1      (przekazanie z = 3)
        //
        // Warstwa wyjściowa j=0 (szerokość 2):
        // V_0[0] = 1
        // V_0[1] = V_1[1] * V_1[2] - 7  ( (8 * 3) - 7 = 24 - 7 = 17 = 0 mod 17 )

        let layer1 = CircuitLayer::<F17>::new(
            1,
            4,
            3,
            vec![
                QuadGate::add(1, 1, 2), // V_1[1] = V_2[1] + V_2[2]
                QuadGate::scale(2, 3, F17::one()), // V_1[2] = V_2[3]
            ],
        );

        let layer0 = CircuitLayer::<F17>::new(
            0,
            3,
            2,
            vec![
                // V_0[1] = V_1[1] * V_1[2] - 7
                QuadGate::new(
                    1,
                    vec![
                        crate::circuit::gate::QuadTerm::mul(1, 2), // V_1[1] * V_1[2]
                        crate::circuit::gate::QuadTerm::constant(-F17::from(7u64)), // - 7
                    ],
                ),
            ],
        );

        let circuit = LayeredCircuit::<F17>::new(vec![layer0, layer1], 4);
        assert_eq!(circuit.depth(), 2);

        // Prawidłowe wejście: x=3, y=5, z=3
        let valid_inputs = vec![F17::one(), F17::from(3u64), F17::from(5u64), F17::from(3u64)];
        assert!(circuit.is_satisfied(&valid_inputs));

        // Błędne wejście: x=3, y=5, z=4  => (3+5)*4 = 32 mod 17 = 15 != 7
        let invalid_inputs = vec![F17::one(), F17::from(3u64), F17::from(5u64), F17::from(4u64)];
        assert!(!circuit.is_satisfied(&invalid_inputs));
    }
}
