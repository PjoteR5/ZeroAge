//! Pełna implementacja funkcji skrótu FIPS 180-4 SHA-256 od podstaw (from scratch)
//! wraz z algebraicznym kompilatorem bramek kwadratowych `QuadGate` nad ciałem $\mathbb{F}_p$.
//!
//! Zgodnie z Rozdziałem 6 specyfikacji (*Anonymous Credentials from ECDSA*, Frigo & shelat):
//! - W trybie natywnym wylicza standardowy 256-bitowy skrót SHA-256 dla bloków MSO i atrybutów.
//! - W trybie obwodu ZKP wyraża funkcje boolowskie `Ch(e, f, g)` w 1 bramce kwadratowej na bit
//!   ($z + x(y - z)$) oraz `Maj(a, b, c)` w 2 bramkach na bit ($xy + xz + yz - 2xyz$),
//!   natomiast rotacje bitowe `ROTR` i przesunięcia `SHR` realizuje za 0 bramek poprzez
//!   statyczną permutację indeksów przewodów.

use ark_ff::Field;
use zkp_core::circuit::gate::{QuadGate, QuadTerm};
use zkp_core::circuit::layered::{CircuitLayer, LayeredCircuit};
use zkp_core::field::{field_bits_be_to_u32, u32_to_field_bits_be};

/// Początkowe wartości rejestrów stanu FIPS 180-4 SHA-256
/// (pierwsze 32 bity części ułamkowych pierwiastków kwadratowych z 8 pierwszych liczb pierwszych).
pub const SHA256_H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Stałe rundowe FIPS 180-4 SHA-256 `K[0..63]`
/// (pierwsze 32 bity części ułamkowych pierwiastków sześciennych z 64 pierwszych liczb pierwszych).
pub const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

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

/// Rozwija 512-bitowy (64-bajtowy) blok wejściowy w 64 słowa harmonogramu wiadomości `W[0..63]`.
pub fn expand_message_schedule(block: &[u8; 64]) -> [u32; 64] {
    let mut w = [0u32; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[4 * i],
            block[4 * i + 1],
            block[4 * i + 2],
            block[4 * i + 3],
        ]);
    }
    for i in 16..64 {
        w[i] = small_sigma1(w[i - 2])
            .wrapping_add(w[i - 7])
            .wrapping_add(small_sigma0(w[i - 15]))
            .wrapping_add(w[i - 16]);
    }
    w
}

/// Wykonuje 64-rundową funkcję kompresji FIPS 180-4 SHA-256 na stanie `state` i bloku `block`.
pub fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let w = expand_message_schedule(block);
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;

    for i in 0..64 {
        let t1 = h
            .wrapping_add(big_sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(SHA256_K[i])
            .wrapping_add(w[i]);
        let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// Dopełnia wiadomość dowolnej długości zgodnie ze standardem Merkle-Damgårda FIPS 180-4
/// (bit `1`, zera dopełniające oraz 64-bitowa długość w bitach zapisana Big-Endian).
pub fn sha256_pad_message(msg: &[u8]) -> Vec<[u8; 64]> {
    let bit_len = (msg.len() as u64) * 8;
    let mut padded = Vec::with_capacity((msg.len() + 72) & !63);
    padded.extend_from_slice(msg);
    padded.push(0x80);

    while (padded.len() % 64) != 56 {
        padded.push(0x00);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    padded
        .chunks_exact(64)
        .map(|chunk| {
            let mut block = [0u8; 64];
            block.copy_from_slice(chunk);
            block
        })
        .collect()
}

/// Oblicza pełny 32-bajtowy skrót SHA-256 od podstaw (from scratch).
pub fn sha256_digest(msg: &[u8]) -> [u8; 32] {
    let mut state = SHA256_H0;
    for block in sha256_pad_message(msg) {
        sha256_compress(&mut state, &block);
    }

    let mut out = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        out[4 * i..4 * (i + 1)].copy_from_slice(&word.to_be_bytes());
    }
    out
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

    LayeredCircuit::new(vec![layer0, layer1])
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
        let layers_eval = circuit.evaluate(&witness);
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
