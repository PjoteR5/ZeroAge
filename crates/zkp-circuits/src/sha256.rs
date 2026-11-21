use ark_ff::Field;
use zkp_core::circuit::gate::{QuadGate, QuadTerm};
use zkp_core::circuit::layered::{CircuitLayer, LayeredCircuit};
use zkp_core::field::{field_bits_be_to_u32, u32_to_field_bits_be};
pub use zkp_core::sha256::{compress, pad, sha256, H0, K};

/// Aliasy stałych dla pełnej kompatybilności z modułami obwodów
pub const SHA256_H0: [u32; 8] = H0;
pub const SHA256_K: [u32; 64] = K;

/// Funkcja wyboru bitowego `Ch(x, y, z) = (x & y) ^ (!x & z)`.
#[inline(always)]
pub const fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

/// Funkcja większościowa `Maj(x, y, z) = (x & y) ^ (x & z) ^ (y & z)`.
#[inline(always)]
pub const fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

/// Górna funkcja dyfuzyjna $\Sigma_0(x) = \text{ROTR}^2(x) \oplus \text{ROTR}^{13}(x) \oplus \text{ROTR}^{22}(x)$.
#[inline(always)]
pub const fn big_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

/// Górna funkcja dyfuzyjna $\Sigma_1(x) = \text{ROTR}^6(x) \oplus \text{ROTR}^{11}(x) \oplus \text{ROTR}^{25}(x)$.
#[inline(always)]
pub const fn big_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

/// Dolna funkcja harmonogramu wiadomości $\sigma_0(x) = \text{ROTR}^7(x) \oplus \text{ROTR}^{18}(x) \oplus (x \gg 3)$.
#[inline(always)]
pub const fn small_sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

/// Dolna funkcja harmonogramu wiadomości $\sigma_1(x) = \text{ROTR}^{17}(x) \oplus \text{ROTR}^{19}(x) \oplus (x \gg 10)$.
#[inline(always)]
pub const fn small_sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

/// Wykonuje 64-rundową funkcję kompresji FIPS 180-4 SHA-256 (deleguje do `compress` z gałęzi Jakub).
pub fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    compress(state, block);
}

/// Dopełnia wiadomość za pomocą funkcji `pad` (z gałęzi Jakub) i dzieli na 64-bajtowe bloki.
pub fn sha256_pad_message(msg: &[u8]) -> Vec<[u8; 64]> {
    pad(msg)
        .chunks_exact(64)
        .map(|chunk| {
            let mut block = [0u8; 64];
            block.copy_from_slice(chunk);
            block
        })
        .collect()
}

/// Oblicza pełny 32-bajtowy skrót SHA-256 wywołując bezpośrednio funkcję `sha256` z gałęzi Jakub.
pub fn sha256_digest(msg: &[u8]) -> [u8; 32] {
    sha256(msg)
}

// ===========================================================================
// Gadżety Obwodu Kwadratowego SHA-256 nad Ciałem Skończonym F_p
// ===========================================================================

/// Bezkosztowa (0 bramek!) rotacja w prawo `ROTR^k` tablicy 32 przewodów bitowych (MSB-first).
pub fn rotr32_wires(wires: &[usize; 32], k: usize) -> [usize; 32] {
    let shift = k % 32;
    let mut out = [0usize; 32];
    for i in 0..32 {
        out[i] = wires[(i + 32 - shift) % 32];
    }
    out
}

/// Bezkosztowe (0 bramek!) przesunięcie logiczne w prawo `SHR^k` tablicy 32 przewodów bitowych.
pub fn shr32_wires(wires: &[usize; 32], k: usize, zero_wire: usize) -> [usize; 32] {
    let mut out = [zero_wire; 32];
    if k < 32 {
        for i in k..32 {
            out[i] = wires[i - k];
        }
    }
    out
}

/// Buduje dwuwarstwowy obwód arytmetyczny (`LayeredCircuit<F>`) obliczający jednocześnie
/// 32-bitowe operacje nieliniowe rundy SHA-256:
/// - `Ch(e, f, g)` na przewodach wyjściowych `1..=32`,
/// - `Maj(a, b, c)` na przewodach wyjściowych `33..=64`,
/// oraz weryfikujący binarność wszystkich $6 \times 32 = 192$ bitów wejściowych na przewodach `65..=256`.
///
/// Układ przewodów warstwy wejściowej (szerokość 193):
/// - `wire 0`: stała `1`
/// - `wires 1..=32`: bity rejestru `e` (MSB-first)
/// - `wires 33..=64`: bity rejestru `f`
/// - `wires 65..=96`: bity rejestru `g`
/// - `wires 97..=128`: bity rejestru `a`
/// - `wires 129..=160`: bity rejestru `b`
/// - `wires 161..=192`: bity rejestru `c`
pub fn build_sha256_round_nonlinear_circuit<F: Field>() -> LayeredCircuit<F> {
    // Warstwa pośrednia (Layer 1, wejście z warstwy 2 o szerokości 193, wyjście o szerokości 257):
    // - przewód 0: stała 1
    // - przewody 1..=192: przekazane bez zmian bity (e, f, g, a, b, c)
    // - przewody 193..=224: iloczyny pomocnicze xy_i = a_i * b_i (potrzebne do Maj w 1 kroku kwadratowym)
    // - przewody 225..=256: suma kwadratów błędów binarności b_k^2 - b_k (w grupach po 6 bitów)
    let mut gates_layer1 = Vec::new();
    for w in 1..=192 {
        gates_layer1.push(QuadGate::scale(w, w, F::one()));
    }
    for i in 0..32 {
        let a_w = 97 + i;
        let b_w = 129 + i;
        let xy_w = 193 + i;
        gates_layer1.push(QuadGate::and_bit(xy_w, a_w, b_w));
    }
    for i in 0..32 {
        let bit_check_out = 225 + i;
        let mut terms = Vec::with_capacity(12);
        for reg in 0..6 {
            let w = 1 + reg * 32 + i;
            terms.push(QuadTerm::mul(w, w));
            terms.push(QuadTerm::linear(w, -F::one()));
        }
        gates_layer1.push(QuadGate::new(bit_check_out, terms));
    }
    let layer1 = CircuitLayer::new(1, 193, 257, gates_layer1);

    // Warstwa wyjściowa (Layer 0, wejście z warstwy 1 o szerokości 257, wyjście o szerokości 97):
    // - przewód 0: stała 1
    // - przewody 1..=32: bity wyniku Ch(e, f, g)
    // - przewody 33..=64: bity wyniku Maj(a, b, c)
    // - przewody 65..=96: więzy binarności (powinny wynosić 0 dla poprawnych bitów)
    let mut gates_layer0 = Vec::new();
    for i in 0..32 {
        let e_w = 1 + i;
        let f_w = 33 + i;
        let g_w = 65 + i;
        gates_layer0.push(QuadGate::sha256_ch_bit(1 + i, e_w, f_w, g_w));

        let a_w = 97 + i;
        let b_w = 129 + i;
        let c_w = 161 + i;
        let xy_w = 193 + i;
        gates_layer0.push(QuadGate::sha256_maj_from_xy(33 + i, a_w, b_w, c_w, xy_w));

        gates_layer0.push(QuadGate::scale(65 + i, 225 + i, F::one()));
    }
    let layer0 = CircuitLayer::new(0, 257, 97, gates_layer0);

    LayeredCircuit::new(vec![layer0, layer1], 193)
}

/// Buduje wektor świadka wejściowego (długość 193) dla obwodu `build_sha256_round_nonlinear_circuit`
/// na podstawie sześciu 32-bitowych rejestrów stanu SHA-256 `(e, f, g, a, b, c)`.
pub fn build_sha256_round_witness<F: Field>(
    e: u32,
    f: u32,
    g: u32,
    a: u32,
    b: u32,
    c: u32,
) -> Vec<F> {
    let mut witness = Vec::with_capacity(193);
    witness.push(F::one());
    for word in [e, f, g, a, b, c] {
        witness.extend_from_slice(&u32_to_field_bits_be::<F>(word));
    }
    witness
}

/// Wyodrębnia z warstwy wyjściowej `V_0` obwodu nieliniowego SHA-256 obliczone słowa
/// `(Ch(e, f, g), Maj(a, b, c))` oraz informację, czy wszystkie więzy binarności są zerowe.
pub fn extract_sha256_round_outputs<F: Field>(v_out: &[F]) -> (u32, u32, bool) {
    assert_eq!(v_out.len(), 97);
    let mut ch_bits = [F::zero(); 32];
    let mut maj_bits = [F::zero(); 32];
    ch_bits.copy_from_slice(&v_out[1..33]);
    maj_bits.copy_from_slice(&v_out[33..65]);

    let all_bits_valid = v_out[65..97].iter().all(|v| v.is_zero());
    (
        field_bits_be_to_u32(&ch_bits),
        field_bits_be_to_u32(&maj_bits),
        all_bits_valid,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256 as OfficialSha256};
    use zkp_core::field::Fp256;

    #[test]
    fn test_sha256_from_scratch_matches_nist_vectors() {
        let test_messages: [&[u8]; 4] = [
            b"",
            b"abc",
            b"ZeroAge-Anonymous-Credentials-From-ECDSA-MSO-Digest-Test",
            &[0x5au8; 200], // Wiadomość wieloblokowa (> 3 bloki po 64 bajty)
        ];

        for msg in test_messages {
            let our_digest = sha256_digest(msg);
            let mut official = OfficialSha256::new();
            official.update(msg);
            let expected: [u8; 32] = official.finalize().into();
            assert_eq!(
                our_digest, expected,
                "Niezgodność skrótu SHA-256 dla wiadomości o długości {}",
                msg.len()
            );
        }
    }

    #[test]
    fn test_sha256_algebraic_circuit_matches_native_ch_and_maj() {
        let circuit = build_sha256_round_nonlinear_circuit::<Fp256>();

        // Rejestry początkowe SHA-256 H0
        let (a, b, c) = (SHA256_H0[0], SHA256_H0[1], SHA256_H0[2]);
        let (e, f, g) = (SHA256_H0[4], SHA256_H0[5], SHA256_H0[6]);

        let witness = build_sha256_round_witness::<Fp256>(e, f, g, a, b, c);
        let layers_eval = circuit.evaluate_all(&witness);
        let v_out = &layers_eval[0];

        let (circuit_ch, circuit_maj, bits_ok) = extract_sha256_round_outputs(v_out);
        assert!(bits_ok, "Więzy binarności w obwodzie SHA-256 muszą być spełnione");
        assert_eq!(circuit_ch, ch(e, f, g));
        assert_eq!(circuit_maj, maj(a, b, c));
    }

    #[test]
    fn test_wire_rotations_are_exact() {
        let mut wires = [0usize; 32];
        for i in 0..32 {
            wires[i] = i + 1;
        }
        let rot2 = rotr32_wires(&wires, 2);
        assert_eq!(rot2[0], wires[30]);
        assert_eq!(rot2[1], wires[31]);
        assert_eq!(rot2[2], wires[0]);
    }
}
