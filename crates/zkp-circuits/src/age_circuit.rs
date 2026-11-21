use ark_ff::Field;
use zkp_core::circuit::gate::{QuadGate, QuadTerm};
use zkp_core::circuit::layered::{CircuitLayer, LayeredCircuit};
use zkp_core::field::u64_to_field_bits_le;

/// Liczba sekund odpowiadająca 18 latom (używana pomocniczo przez Wystawcę przy emisji certyfikatu).
pub const AGE_18_SECONDS: u64 = (18 * 365 + 4) * 86_400; // 567_993_600 sekund

/// Indeksy przewodów wejściowych w obwodzie weryfikacji flagi `is_over18` i ważności certyfikatu (szerokość 136):
/// - `wire 0`: stała `1` (wejście publiczne)
/// - `wire 1`: publiczny czas weryfikacji `t_now` (wejście publiczne)
/// - `wire 2`: publiczny skrót zobowiązania atrybutu `is_over18` z MSO (`mso_attr_digest_field`, wejście publiczne)
/// - `wire 3`: prywatna flaga `is_over18` z certyfikatu (`1` = pełnoletni, `0` = niepełnoletni)
/// - `wire 4`: początek ważności certyfikatu `valid_from`
/// - `wire 5`: koniec ważności certyfikatu `valid_until`
/// - `wire 6`: prywatny skrót atrybutu `is_over18` wyliczony z flagi i soli (`witness_attr_digest_field`)
/// - `wires 7..71`: 64 bity różnicy $\Delta_{\text{from}} = t_{\text{now}} - \text{valid\_from}$
/// - `wires 71..135`: 64 bity różnicy $\Delta_{\text{until}} = \text{valid\_until} - t_{\text{now}}$
/// - `wire 135`: przewód dopełniający (0)
pub const AGE_CIRCUIT_IN_WIDTH: usize = 136;
pub const AGE_CIRCUIT_OUT_WIDTH: usize = 135;

/// Pomocnicza funkcja budująca bramkę rekonstrukcji 64-bitowej:
/// $\left(\sum_{i=0}^{63} 2^i \cdot b_i\right) - \Delta = 0$.
fn build_64bit_reconstruction_gate<F: Field>(
    out_wire: usize,
    first_bit_wire: usize,
    mut delta_terms: Vec<QuadTerm<F>>,
) -> QuadGate<F> {
    let two = F::from(2u64);
    let mut power = F::one();
    let mut terms = Vec::with_capacity(64 + delta_terms.len());

    for i in 0..64 {
        terms.push(QuadTerm::linear(first_bit_wire + i, power));
        power *= two;
    }
    terms.append(&mut delta_terms);
    QuadGate::new(out_wire, terms)
}

/// Buduje obwód kwadratowy weryfikujący:
/// 1. Binarność flagi `is_over18 in {0, 1}` (`wire 3^2 - wire 3 == 0`),
/// 2. Spełnienie warunku pełnoletności `is_over18 == 1` (`wire 3 - wire 0 == 0`),
/// 3. Aktywność certyfikatu `t_now >= valid_from` (64-bitowy test zakresu chroniący przed przepełnieniem $p-1$),
/// 4. Brak wygaśnięcia certyfikatu `valid_until >= t_now` (64-bitowy test zakresu chroniący przed przepełnieniem $p-1$),
/// 5. Zgodność zobowiązania `SHA-256("is_over18", is_over18, salt)` z podpisem Wystawcy (`wire 2 - wire 6 == 0`).
pub fn build_age_and_validity_circuit<F: Field>() -> LayeredCircuit<F> {
    let mut gates = Vec::with_capacity(134);

    // 1: Więz binarności flagi is_over18: w[3]^2 - w[3] == 0
    gates.push(QuadGate::assert_bit(1, 3));

    // 2: Wymóg pełnoletności (Algorytm 9 / 10 Frigo & shelat): is_over18 - 1 == 0
    gates.push(QuadGate::sub(2, 3, 0));

    // 3..=66: Więzy binarności u_i^2 - u_i == 0 dla 64 bitów Delta_from (wires 7..71)
    for i in 0..64 {
        gates.push(QuadGate::assert_bit(3 + i, 7 + i));
    }
    // 67: Rekonstrukcja sum_{i=0..63} 2^i * u_i - (t_now - valid_from) == 0
    gates.push(build_64bit_reconstruction_gate(
        67,
        7,
        vec![
            QuadTerm::linear(1, -F::one()), // -t_now
            QuadTerm::linear(4, F::one()),  // +valid_from
        ],
    ));

    // 68..=131: Więzy binarności v_i^2 - v_i == 0 dla 64 bitów Delta_until (wires 71..135)
    for i in 0..64 {
        gates.push(QuadGate::assert_bit(68 + i, 71 + i));
    }
    // 132: Rekonstrukcja sum_{i=0..63} 2^i * v_i - (valid_until - t_now) == 0
    gates.push(build_64bit_reconstruction_gate(
        132,
        71,
        vec![
            QuadTerm::linear(5, -F::one()), // -valid_until
            QuadTerm::linear(1, F::one()),  // +t_now
        ],
    ));

    // 133: Zgodność zobowiązania SHA-256 atrybutu is_over18 z certyfikatem MSO: mso_attr_digest - witness_attr_digest == 0
    gates.push(QuadGate::assert_equal(133, 2, 6));

    // 134: Więz zerujący przewód dopełniający wire 135 == 0
    gates.push(QuadGate::scale(134, 135, F::one()));

    let layer = CircuitLayer::new(0, AGE_CIRCUIT_IN_WIDTH, AGE_CIRCUIT_OUT_WIDTH, gates);
    LayeredCircuit::new(vec![layer], AGE_CIRCUIT_IN_WIDTH)
}

/// Generuje wektor świadka o długości `AGE_CIRCUIT_IN_WIDTH` (136) dla obwodu flagi `is_over18` i ważności certyfikatu.
pub fn build_age_and_validity_witness<F: Field>(
    t_now: u64,
    is_over18: bool,
    valid_from: u64,
    valid_until: u64,
    mso_attr_digest_field: F,
    witness_attr_digest_field: F,
) -> Vec<F> {
    let delta_from = t_now.wrapping_sub(valid_from);
    let delta_until = valid_until.wrapping_sub(t_now);

    let mut w = Vec::with_capacity(AGE_CIRCUIT_IN_WIDTH);
    w.push(F::one());                                          // wire 0: 1
    w.push(F::from(t_now));                                    // wire 1: t_now
    w.push(mso_attr_digest_field);                             // wire 2: publiczny digest z MSO
    w.push(if is_over18 { F::one() } else { F::zero() });      // wire 3: flaga is_over18
    w.push(F::from(valid_from));                               // wire 4: valid_from
    w.push(F::from(valid_until));                              // wire 5: valid_until
    w.push(witness_attr_digest_field);                         // wire 6: prywatny digest atrybutu is_over18

    w.extend_from_slice(&u64_to_field_bits_le::<F>(delta_from));  // wires 7..71
    w.extend_from_slice(&u64_to_field_bits_le::<F>(delta_until)); // wires 71..135
    w.push(F::zero());                                            // wire 135: padding

    w
}

/// Sprawdza, czy wszystkie bramki ograniczeń w warstwie wyjściowej `V_0[1..]` wynoszą zero.
pub fn is_age_circuit_output_satisfied<F: Field>(v_out: &[F]) -> bool {
    v_out.len() == AGE_CIRCUIT_OUT_WIDTH
        && v_out[0] == F::one()
        && v_out[1..].iter().all(|val| val.is_zero())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkp_core::field::Fp256;

    #[test]
    fn test_valid_adult_flag_satisfies_age_circuit() {
        let circuit = build_age_and_validity_circuit::<Fp256>();
        let t_now = 1_794_064_800u64; // 2026-11-07
        let valid_from = t_now - 3_600;
        let valid_until = t_now + 86_400 * 365;
        let digest_field = Fp256::from(0x1234_5678_9abc_def0u64);

        let witness = build_age_and_validity_witness(
            t_now,
            true, // is_over18 = true
            valid_from,
            valid_until,
            digest_field,
            digest_field,
        );
        let evals = circuit.evaluate_all(&witness);
        assert!(is_age_circuit_output_satisfied(&evals[0]));
    }

    #[test]
    fn test_underage_flag_false_is_rejected_by_circuit() {
        let circuit = build_age_and_validity_circuit::<Fp256>();
        let t_now = 1_794_064_800u64;
        let valid_from = t_now - 3_600;
        let valid_until = t_now + 86_400 * 365;
        let digest_field = Fp256::from(42u64);

        let witness = build_age_and_validity_witness(
            t_now,
            false, // is_over18 = false (niepełnoletni!)
            valid_from,
            valid_until,
            digest_field,
            digest_field,
        );
        let evals = circuit.evaluate_all(&witness);
        assert!(
            !is_age_circuit_output_satisfied(&evals[0]),
            "Certyfikat z flagą is_over18 = false musi zostać odrzucony przez obwód!"
        );
    }

    #[test]
    fn test_expired_credential_underflow_is_rejected_by_circuit() {
        let circuit = build_age_and_validity_circuit::<Fp256>();
        let t_now = 1_794_064_800u64;
        let valid_from = t_now - 86_400 * 30;
        let valid_until = t_now - 60; // Wygasło minutę temu (próba przepełnienia p - 1)!
        let digest_field = Fp256::from(42u64);

        let witness = build_age_and_validity_witness(
            t_now,
            true,
            valid_from,
            valid_until,
            digest_field,
            digest_field,
        );
        let evals = circuit.evaluate_all(&witness);
        assert!(!is_age_circuit_output_satisfied(&evals[0]));
    }
}
