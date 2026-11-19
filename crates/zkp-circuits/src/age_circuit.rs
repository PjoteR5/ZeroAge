use ark_ff::Field;
use zkp_core::circuit::gate::{QuadGate, QuadTerm};
use zkp_core::circuit::layered::{CircuitLayer, LayeredCircuit};
use zkp_core::field::u64_to_field_bits_le;

/// Liczba sekund odpowiadająca 18 latom (z uwzględnieniem gwarantowanych $\ge 4$ dni przestępnych).
pub const AGE_18_SECONDS: u64 = (18 * 365 + 4) * 86_400; // 567_993_600 sekund

/// Indeksy przewodów wejściowych w obwodzie weryfikacji wieku i ważności poświadczenia (szerokość 200):
/// - `wire 0`: stała `1`
/// - `wire 1`: publiczny czas weryfikacji `t_now`
/// - `wire 2`: publiczny skrót atrybutu z MSO (`mso_attr_digest_field`)
/// - `wire 3`: prywatna data urodzenia `dob_timestamp`
/// - `wire 4`: prywatny początek ważności `valid_from`
/// - `wire 5`: prywatny koniec ważności `valid_until`
/// - `wire 6`: prywatny skrót atrybutu wyliczony przez portfel (`witness_attr_digest_field`)
/// - `wires 7..71`: 64 bity różnicy wieku $\Delta_{\text{age}} = t_{\text{now}} - \text{dob} - \text{AGE\_18}$
/// - `wires 71..135`: 64 bity różnicy $\Delta_{\text{from}} = t_{\text{now}} - \text{valid\_from}$
/// - `wires 135..199`: 64 bity różnicy $\Delta_{\text{until}} = \text{valid\_until} - t_{\text{now}}$
/// - `wire 199`: przewód dopełniający (0)
pub const AGE_CIRCUIT_IN_WIDTH: usize = 200;
pub const AGE_CIRCUIT_OUT_WIDTH: usize = 197;

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

pub fn build_age_and_validity_circuit<F: Field>() -> LayeredCircuit<F> {
    let mut gates = Vec::with_capacity(196);
    let age_18_f = F::from(AGE_18_SECONDS);

    // 1..=64: Więzy binarności b_i^2 - b_i == 0 dla 64 bitów Delta_age (wires 7..71)
    for i in 0..64 {
        gates.push(QuadGate::assert_bit(1 + i, 7 + i));
    }
    // 65: Rekonstrukcja sum_{i=0..63} 2^i * b_i - (t_now - dob - AGE_18_SECONDS) == 0
    gates.push(build_64bit_reconstruction_gate(
        65,
        7,
        vec![
            QuadTerm::linear(1, -F::one()),   // -t_now
            QuadTerm::linear(3, F::one()),    // +dob_timestamp
            QuadTerm::constant(age_18_f),     // +AGE_18_SECONDS
        ],
    ));

    // 66..=129: Więzy binarności u_i^2 - u_i == 0 dla 64 bitów Delta_from (wires 71..135)
    for i in 0..64 {
        gates.push(QuadGate::assert_bit(66 + i, 71 + i));
    }
    // 130: Rekonstrukcja sum_{i=0..63} 2^i * u_i - (t_now - valid_from) == 0
    gates.push(build_64bit_reconstruction_gate(
        130,
        71,
        vec![
            QuadTerm::linear(1, -F::one()),   // -t_now
            QuadTerm::linear(4, F::one()),    // +valid_from
        ],
    ));

    // 131..=194: Więzy binarności v_i^2 - v_i == 0 dla 64 bitów Delta_until (wires 135..199)
    for i in 0..64 {
        gates.push(QuadGate::assert_bit(131 + i, 135 + i));
    }
    // 195: Rekonstrukcja sum_{i=0..63} 2^i * v_i - (valid_until - t_now) == 0
    gates.push(build_64bit_reconstruction_gate(
        195,
        135,
        vec![
            QuadTerm::linear(5, -F::one()),   // -valid_until
            QuadTerm::linear(1, F::one()),    // +t_now
        ],
    ));

    // 196: Zgodność skrótu SHA-256 atrybutu z MSO: mso_attr_digest - witness_attr_digest == 0
    gates.push(QuadGate::assert_equal(196, 2, 6));

    let layer = CircuitLayer::new(0, AGE_CIRCUIT_IN_WIDTH, AGE_CIRCUIT_OUT_WIDTH, gates);
    LayeredCircuit::new(vec![layer], AGE_CIRCUIT_IN_WIDTH)
}

/// Generuje wektor świadka o długości `AGE_CIRCUIT_IN_WIDTH` (200) dla obwodu wieku i ważności.
/// Nawet jeśli świadek dotyczy osoby niepełnoletniej (np. w testach ataków), funkcja konstruuje
/// wektor z obciętymi bitami `wrapping_sub`, aby umożliwić przetestowanie odrzucenia przez obwód.
pub fn build_age_and_validity_witness<F: Field>(
    t_now: u64,
    dob_timestamp: u64,
    valid_from: u64,
    valid_until: u64,
    mso_attr_digest_field: F,
    witness_attr_digest_field: F,
) -> Vec<F> {
    let delta_age = t_now
        .wrapping_sub(dob_timestamp)
        .wrapping_sub(AGE_18_SECONDS);
    let delta_from = t_now.wrapping_sub(valid_from);
    let delta_until = valid_until.wrapping_sub(t_now);

    let mut w = Vec::with_capacity(AGE_CIRCUIT_IN_WIDTH);
    w.push(F::one());                      // wire 0: 1
    w.push(F::from(t_now));                // wire 1: t_now
    w.push(mso_attr_digest_field);         // wire 2: publiczny digest z MSO
    w.push(F::from(dob_timestamp));        // wire 3: dob_timestamp
    w.push(F::from(valid_from));           // wire 4: valid_from
    w.push(F::from(valid_until));          // wire 5: valid_until
    w.push(witness_attr_digest_field);     // wire 6: prywatny digest atrybutu

    w.extend_from_slice(&u64_to_field_bits_le::<F>(delta_age));   // wires 7..71
    w.extend_from_slice(&u64_to_field_bits_le::<F>(delta_from));  // wires 71..135
    w.extend_from_slice(&u64_to_field_bits_le::<F>(delta_until)); // wires 135..199
    w.push(F::zero());                                            // wire 199: padding

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
    fn test_valid_adult_satisfies_age_circuit() {
        let circuit = build_age_and_validity_circuit::<Fp256>();
        let t_now = 1_794_064_800u64; // 2026-11-07
        let dob_21yo = t_now - (21 * 365 + 5) * 86_400;
        let valid_from = t_now - 3_600;
        let valid_until = t_now + 86_400 * 365;
        let digest_field = Fp256::from(0x1234_5678_9abc_def0u64);

        let witness = build_age_and_validity_witness(
            t_now,
            dob_21yo,
            valid_from,
            valid_until,
            digest_field,
            digest_field,
        );
        let evals = circuit.evaluate_all(&witness);
        assert!(is_age_circuit_output_satisfied(&evals[0]));
    }

    #[test]
    fn test_underage_17yo_underflow_attack_is_rejected_by_circuit() {
        let circuit = build_age_and_validity_circuit::<Fp256>();
        let t_now = 1_794_064_800u64;
        let dob_17yo = t_now - (17 * 365) * 86_400; // 17-latek (< 18 lat!)
        let valid_from = t_now - 3_600;
        let valid_until = t_now + 86_400 * 365;
        let digest_field = Fp256::from(42u64);

        let witness = build_age_and_validity_witness(
            t_now,
            dob_17yo,
            valid_from,
            valid_until,
            digest_field,
            digest_field,
        );
        let evals = circuit.evaluate_all(&witness);
        assert!(
            !is_age_circuit_output_satisfied(&evals[0]),
            "Atak niedomiaru modularnego 17-latka musi zostać odrzucony przez 64-bitową bramkę zakresu!"
        );
    }

    #[test]
    fn test_expired_credential_is_rejected_by_circuit() {
        let circuit = build_age_and_validity_circuit::<Fp256>();
        let t_now = 1_794_064_800u64;
        let dob_adult = t_now - (25 * 365) * 86_400;
        let valid_from = t_now - 86_400 * 30;
        let valid_until = t_now - 60; // Wygasło minutę temu!
        let digest_field = Fp256::from(42u64);

        let witness = build_age_and_validity_witness(
            t_now,
            dob_adult,
            valid_from,
            valid_until,
            digest_field,
            digest_field,
        );
        let evals = circuit.evaluate_all(&witness);
        assert!(!is_age_circuit_output_satisfied(&evals[0]));
    }
}
