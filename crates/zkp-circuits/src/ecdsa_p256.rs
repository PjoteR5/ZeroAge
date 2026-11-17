//! Natywna arytmetyka krzywej eliptycznej **NIST P-256 (`secp256r1`, FIPS 186-4)**,
//! podpisy **ECDSA P-256 z SHA-256** oraz obwód weryfikacji punktów ECDSA (Algorytm 4
//! z artykułu Frigo & shelat, *Anonymous Credentials from ECDSA*) nad ciałem $\mathbb{F}_{p_{256}}$.

#![allow(non_local_definitions)]

use ark_ff::{BigInt, Field, Fp256 as ArkFp256, MontBackend, MontConfig, One, PrimeField, Zero};

use crate::sha256::sha256_digest;
use zkp_core::circuit::gate::{QuadGate, QuadTerm};
use zkp_core::circuit::layered::{CircuitLayer, LayeredCircuit};
use zkp_core::field::Fp256;

/// Ciało skalarne krzywej NIST P-256 ($\mathbb{F}_{n_{256}}$) – rząd grupy punktów $G$:
/// $n_{256} = \text{0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551}$
/// $= 115792089210356248762697446949407573529996955224135760342422259061068512044369$.
#[derive(MontConfig)]
#[modulus = "115792089210356248762697446949407573529996955224135760342422259061068512044369"]
#[generator = "7"]
pub struct P256ScalarConfig;

/// Element ciała skalarnego $\mathbb{F}_{n_{256}}$ krzywej NIST P-256.
pub type Fr256 = ArkFp256<MontBackend<P256ScalarConfig, 4>>;

/// Punkt afiniczny na krzywej krótkiej Weierstrassa NIST P-256:
/// $y^2 \equiv x^3 - 3x + b \pmod{p_{256}}$.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct P256Point {
    pub x: Fp256,
    pub y: Fp256,
    pub infinity: bool,
}

impl P256Point {
    /// Punkt w nieskończoności $\mathcal{O}$ (element neutralny grupy).
    pub fn identity() -> Self {
        Self {
            x: Fp256::zero(),
            y: Fp256::zero(),
            infinity: true,
        }
    }

    /// Tworzy punkt afiniczny $(x, y)$ na krzywej P-256.
    pub fn new(x: Fp256, y: Fp256) -> Self {
        Self {
            x,
            y,
            infinity: false,
        }
    }

    /// Stała $b$ równania krzywej NIST P-256:
    /// `b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b`.
    pub fn curve_b() -> Fp256 {
        Fp256::from_bigint(BigInt([
            0x3bce3c3e27d2604b,
            0x651d06b0cc53b0f6,
            0xb3ebbd55769886bc,
            0x5ac635d8aa3a93e7,
        ]))
        .expect("Stała b krzywej NIST P-256 musi należeć do F_p256")
    }

    /// Kanoniczny generator grupy $G = (G_x, G_y)$ standardu FIPS 186-4 dla krzywej NIST P-256.
    pub fn generator() -> Self {
        let gx = Fp256::from_bigint(BigInt([
            0xf4a13945d898c296,
            0x77037d812deb33a0,
            0xf8bce6e563a440f2,
            0x6b17d1f2e12c4247,
        ]))
        .expect("Współrzędna G_x musi należeć do F_p256");

        let gy = Fp256::from_bigint(BigInt([
            0xcbb6406837bf51f5,
            0x2bce33576b315ece,
            0x8ee7eb4a7c0f9e16,
            0x4fe342e2fe1a7f9b,
        ]))
        .expect("Współrzędna G_y musi należeć do F_p256");

        Self::new(gx, gy)
    }

    /// Sprawdza, czy punkt spełnia równanie krzywej NIST P-256: $y^2 = x^3 - 3x + b \pmod{p_{256}}$.
    pub fn is_on_curve(&self) -> bool {
        if self.infinity {
            return true;
        }
        let three = Fp256::from(3u64);
        let x2 = self.x * self.x;
        let x3 = x2 * self.x;
        let rhs = x3 - three * self.x + Self::curve_b();
        self.y * self.y == rhs
    }

    /// Punkt przeciwny $-P = (x, -y \bmod p_{256})$.
    pub fn neg(&self) -> Self {
        if self.infinity {
            *self
        } else {
            Self::new(self.x, -self.y)
        }
    }

    /// Podwojenie punktu $[2]P$ na krzywej krótkiej Weierstrassa ($a = -3$).
    pub fn double(&self) -> Self {
        if self.infinity || self.y.is_zero() {
            return Self::identity();
        }
        let two = Fp256::from(2u64);
        let three = Fp256::from(3u64);

        // Nachylenie stycznej: lambda = (3*x^2 - 3) / (2*y)
        let num = three * (self.x * self.x - Fp256::one());
        let den = (two * self.y).inverse().expect("2*y != 0");
        let lambda = num * den;

        let x3 = lambda * lambda - two * self.x;
        let y3 = lambda * (self.x - x3) - self.y;
        Self::new(x3, y3)
    }

    /// Dodawanie dwóch punktów $P + Q$ na krzywej NIST P-256.
    pub fn add(&self, other: &Self) -> Self {
        if self.infinity {
            return *other;
        }
        if other.infinity {
            return *self;
        }
        if self.x == other.x {
            if self.y == other.y {
                return self.double();
            } else {
                return Self::identity();
            }
        }

        let num = other.y - self.y;
        let den = (other.x - self.x).inverse().expect("x2 - x1 != 0");
        let lambda = num * den;

        let x3 = lambda * lambda - self.x - other.x;
        let y3 = lambda * (self.x - x3) - self.y;
        Self::new(x3, y3)
    }

    /// Mnożenie skalarne $[k]P$ metodą double-and-add dla skalara $k \in \mathbb{F}_{n_{256}}$.
    pub fn scalar_mul(&self, scalar: &Fr256) -> Self {
        let bigint = scalar.into_bigint();
        let limbs = bigint.0;
        let mut acc = Self::identity();
        let mut base = *self;

        for limb in limbs {
            for bit_idx in 0..64 {
                if ((limb >> bit_idx) & 1) == 1 {
                    acc = acc.add(&base);
                }
                base = base.double();
            }
        }
        acc
    }
}

/// Konwertuje współrzędną bazową $x \in \mathbb{F}_{p_{256}}$ na skalar $x \bmod n_{256} \in \mathbb{F}_{n_{256}}$.
pub fn fp256_to_fr256_mod_n(x: &Fp256) -> Fr256 {
    let raw = x.into_bigint();
    let mut le_bytes = [0u8; 32];
    for (i, limb) in raw.0.iter().enumerate() {
        le_bytes[8 * i..8 * (i + 1)].copy_from_slice(&limb.to_le_bytes());
    }
    Fr256::from_le_bytes_mod_order(&le_bytes)
}

/// Konwertuje 32-bajtowy skrót SHA-256 (Big-Endian, zgodnie z FIPS 186-4) na skalar $e \in \mathbb{F}_{n_{256}}$.
pub fn sha256_digest_to_scalar(digest_be: &[u8; 32]) -> Fr256 {
    let mut le_bytes = *digest_be;
    le_bytes.reverse();
    Fr256::from_le_bytes_mod_order(&le_bytes)
}

/// Podpis cyfrowy ECDSA nad krzywą NIST P-256: para skalarów $(r, s) \in (\mathbb{F}_{n_{256}}^*)^2$
/// wraz z punktem świadka $R = (R_x, R_y)$ potrzebnym Proverowi w Algorytmie 4 (Frigo & shelat).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EcdsaSignature {
    pub r: Fr256,
    pub s: Fr256,
    pub r_point: P256Point,
}

/// Para kluczy asymetrycznych ECDSA P-256 (klucz prywatny $d \in \mathbb{F}_{n_{256}}^*$ i punkt $Q = [d]G$).
#[derive(Clone, Debug)]
pub struct EcdsaKeyPair {
    pub secret_key: Fr256,
    pub public_key: P256Point,
}

impl EcdsaKeyPair {
    /// Tworzy parę kluczy z zadanego skalara prywatnego $d \neq 0$.
    pub fn from_secret_scalar(secret_key: Fr256) -> Self {
        assert!(!secret_key.is_zero(), "Klucz prywatny ECDSA nie może być zerem");
        let public_key = P256Point::generator().scalar_mul(&secret_key);
        Self {
            secret_key,
            public_key,
        }
    }

    /// Deterministycznie wyprowadza parę kluczy ECDSA P-256 z ziarna (seed) za pomocą SHA-256.
    pub fn from_seed(seed: &[u8]) -> Self {
        let mut counter = 0u32;
        loop {
            let mut input = Vec::with_capacity(seed.len() + 4);
            input.extend_from_slice(seed);
            input.extend_from_slice(&counter.to_be_bytes());
            let digest = sha256_digest(&input);
            let sk = sha256_digest_to_scalar(&digest);
            if !sk.is_zero() {
                return Self::from_secret_scalar(sk);
            }
            counter += 1;
        }
    }

    /// Podpisuje gotowy 32-bajtowy skrót `SHA-256` algorytmem ECDSA P-256 (z deterministycznym nonce'em RFC 6979-like).
    pub fn sign_prehashed(&self, digest_be: &[u8; 32]) -> EcdsaSignature {
        let e = sha256_digest_to_scalar(digest_be);
        let sk_bigint = self.secret_key.into_bigint();

        let mut counter = 0u32;
        loop {
            let mut nonce_input = Vec::with_capacity(72);
            nonce_input.extend_from_slice(b"ZeroAge-P256-ECDSA-Nonce");
            for limb in sk_bigint.0 {
                nonce_input.extend_from_slice(&limb.to_be_bytes());
            }
            nonce_input.extend_from_slice(digest_be);
            nonce_input.extend_from_slice(&counter.to_be_bytes());

            let k_digest = sha256_digest(&nonce_input);
            let k = sha256_digest_to_scalar(&k_digest);
            if !k.is_zero() {
                let r_point = P256Point::generator().scalar_mul(&k);
                if !r_point.infinity {
                    let r = fp256_to_fr256_mod_n(&r_point.x);
                    if !r.is_zero() {
                        let k_inv = k.inverse().expect("k != 0");
                        let s = k_inv * (e + r * self.secret_key);
                        if !s.is_zero() {
                            return EcdsaSignature { r, s, r_point };
                        }
                    }
                }
            }
            counter += 1;
        }
    }

    /// Oblicza skrót SHA-256 wiadomości `msg` (od podstaw) i podpisuje go kluczem ECDSA P-256.
    pub fn sign_message(&self, msg: &[u8]) -> EcdsaSignature {
        let digest = sha256_digest(msg);
        self.sign_prehashed(&digest)
    }
}

/// Weryfikuje podpis ECDSA P-256 nad 32-bajtowym skrótem `SHA-256`:
/// $[e \cdot s^{-1}]G + [r \cdot s^{-1}]Q \stackrel{?}{=} R$ oraz $R_x \bmod n \stackrel{?}{=} r$.
pub fn verify_ecdsa_prehashed(
    public_key: &P256Point,
    digest_be: &[u8; 32],
    sig: &EcdsaSignature,
) -> bool {
    if public_key.infinity || !public_key.is_on_curve() {
        return false;
    }
    if sig.r.is_zero() || sig.s.is_zero() {
        return false;
    }

    let s_inv = match sig.s.inverse() {
        Some(inv) => inv,
        None => return false,
    };
    let e = sha256_digest_to_scalar(digest_be);
    let u1 = e * s_inv;
    let u2 = sig.r * s_inv;

    let p1 = P256Point::generator().scalar_mul(&u1);
    let p2 = public_key.scalar_mul(&u2);
    let r_calc = p1.add(&p2);

    if r_calc.infinity {
        return false;
    }
    let rx_mod_n = fp256_to_fr256_mod_n(&r_calc.x);
    rx_mod_n == sig.r
}

/// Weryfikuje podpis ECDSA P-256 dla surowej wiadomości `msg` (haszowanej SHA-256).
pub fn verify_ecdsa_message(
    public_key: &P256Point,
    msg: &[u8],
    sig: &EcdsaSignature,
) -> bool {
    let digest = sha256_digest(msg);
    verify_ecdsa_prehashed(public_key, &digest, sig)
}

// ===========================================================================
// Obwód Weryfikacji Punktów i Kroku Dodawania ECDSA P-256 (Algorytm 4)
// ===========================================================================

/// Buduje dwuwarstwowy obwód arytmetyczny (`LayeredCircuit<Fp256>`) weryfikujący relacje
/// na krzywej NIST P-256 bez narzutu obcego ciała (bezpośrednio w $\mathbb{F}_{p_{256}}$):
/// 1. Przynależność punktu klucza publicznego $Q = (Q_x, Q_y)$ do krzywej P-256:
///    $Q_y^2 - (Q_x^3 - 3 Q_x + b) = 0$.
/// 2. Przynależność punktu świadka $R = (R_x, R_y)$ do krzywej P-256:
///    $R_y^2 - (R_x^3 - 3 R_x + b) = 0$.
/// 3. Poprawność kroku dodawania punktów krzywej $P_1 + P_2 = R$ ze świadkiem nachylenia $\lambda$:
///    - $\lambda \cdot (x_2 - x_1) - (y_2 - y_1) = 0$,
///    - $\lambda^2 - x_1 - x_2 - R_x = 0$,
///    - $\lambda \cdot (x_1 - R_x) - y_1 - R_y = 0$.
///
/// Układ przewodów wejściowych (szerokość 10):
/// - `wire 0`: stała `1`
/// - `wire 1`: $Q_x$, `wire 2`: $Q_y$
/// - `wire 3`: $R_x$, `wire 4`: $R_y$
/// - `wire 5`: $x_1$, `wire 6`: $y_1$ (punkt $[u_1]G$)
/// - `wire 7`: $x_2$, `wire 8`: $y_2$ (punkt $[u_2]Q$)
/// - `wire 9`: $\lambda$ (nachylenie siecznej $(y_2 - y_1)/(x_2 - x_1)$)
pub fn build_p256_ecdsa_curve_circuit() -> LayeredCircuit<Fp256> {
    let three = Fp256::from(3u64);
    let b_const = P256Point::curve_b();

    // Warstwa 1 (wejście: 10 przewodów, wyjście: 12 przewodów):
    // - przewody 1..=9: przepisane wejścia
    // - przewód 10: Q_x^2 (aby w warstwie 0 obliczyć Q_x^3 = Q_x^2 * Q_x jako stopień 2)
    // - przewód 11: R_x^2 (aby w warstwie 0 obliczyć R_x^3 = R_x^2 * R_x jako stopień 2)
    let mut gates_l1 = Vec::new();
    for w in 1..=9 {
        gates_l1.push(QuadGate::scale(w, w, Fp256::one()));
    }
    gates_l1.push(QuadGate::mul(10, 1, 1)); // Q_x^2
    gates_l1.push(QuadGate::mul(11, 3, 3)); // R_x^2
    let layer1 = CircuitLayer::new(1, 10, 12, gates_l1);

    // Warstwa 0 (wyjście: 6 przewodów; dla poprawnego świadka przewody 1..=5 muszą wynosić 0):
    // - przewód 1: Q_y^2 - Q_x^3 + 3*Q_x - b == 0
    // - przewód 2: R_y^2 - R_x^3 + 3*R_x - b == 0
    // - przewód 3: lambda * (x2 - x1) - (y2 - y1) == 0
    // - przewód 4: lambda^2 - x1 - x2 - R_x == 0
    // - przewód 5: lambda * (x1 - R_x) - y1 - R_y == 0
    let gate_q_curve = QuadGate::new(
        1,
        vec![
            QuadTerm::mul(2, 2),                    // Q_y^2
            QuadTerm::new(10, 1, -Fp256::one()),    // -Q_x^2 * Q_x
            QuadTerm::linear(1, three),             // +3 * Q_x
            QuadTerm::constant(-b_const),           // -b
        ],
    );
    let gate_r_curve = QuadGate::new(
        2,
        vec![
            QuadTerm::mul(4, 4),                    // R_y^2
            QuadTerm::new(11, 3, -Fp256::one()),    // -R_x^2 * R_x
            QuadTerm::linear(3, three),             // +3 * R_x
            QuadTerm::constant(-b_const),           // -b
        ],
    );
    let gate_slope = QuadGate::new(
        3,
        vec![
            QuadTerm::new(9, 7, Fp256::one()),      // lambda * x2
            QuadTerm::new(9, 5, -Fp256::one()),     // -lambda * x1
            QuadTerm::linear(8, -Fp256::one()),     // -y2
            QuadTerm::linear(6, Fp256::one()),      // +y1
        ],
    );
    let gate_rx = QuadGate::new(
        4,
        vec![
            QuadTerm::mul(9, 9),                    // lambda^2
            QuadTerm::linear(5, -Fp256::one()),     // -x1
            QuadTerm::linear(7, -Fp256::one()),     // -x2
            QuadTerm::linear(3, -Fp256::one()),     // -R_x
        ],
    );
    let gate_ry = QuadGate::new(
        5,
        vec![
            QuadTerm::new(9, 5, Fp256::one()),      // lambda * x1
            QuadTerm::new(9, 3, -Fp256::one()),     // -lambda * R_x
            QuadTerm::linear(6, -Fp256::one()),     // -y1
            QuadTerm::linear(4, -Fp256::one()),     // -R_y
        ],
    );

    let layer0 = CircuitLayer::new(
        0,
        12,
        6,
        vec![gate_q_curve, gate_r_curve, gate_slope, gate_rx, gate_ry],
    );
    LayeredCircuit::new(vec![layer0, layer1], 10)
}

/// Generuje wektor świadka wejściowego (długość 10) dla obwodu `build_p256_ecdsa_curve_circuit`
/// na podstawie klucza publicznego $Q$, skrótu `digest_be` i podpisu `sig`.
pub fn build_p256_ecdsa_curve_witness(
    public_key: &P256Point,
    digest_be: &[u8; 32],
    sig: &EcdsaSignature,
) -> Option<Vec<Fp256>> {
    let s_inv = sig.s.inverse()?;
    let e = sha256_digest_to_scalar(digest_be);
    let u1 = e * s_inv;
    let u2 = sig.r * s_inv;

    let p1 = P256Point::generator().scalar_mul(&u1);
    let p2 = public_key.scalar_mul(&u2);
    if p1.infinity || p2.infinity || p1.x == p2.x {
        return None;
    }

    let lambda = (p2.y - p1.y) * (p2.x - p1.x).inverse()?;
    let r_pt = sig.r_point;

    Some(vec![
        Fp256::one(),
        public_key.x,
        public_key.y,
        r_pt.x,
        r_pt.y,
        p1.x,
        p1.y,
        p2.x,
        p2.y,
        lambda,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_p256_generator_and_group_law() {
        let g = P256Point::generator();
        assert!(g.is_on_curve(), "Generator FIPS 186-4 musi leżeć na krzywej NIST P-256");

        let g2 = g.double();
        assert!(g2.is_on_curve());
        let g3 = g2.add(&g);
        assert!(g3.is_on_curve());

        let g3_scalar = g.scalar_mul(&Fr256::from(3u64));
        assert_eq!(g3, g3_scalar);
    }

    #[test]
    fn test_ecdsa_p256_sign_and_verify_with_circuit_witness() {
        let issuer_kp = EcdsaKeyPair::from_seed(b"ZeroAge-Issuer-Secret-Key-Seed");
        let mso_bytes = b"ISO-18013-5-MobileSecurityObject-Payload-v1";
        let digest = sha256_digest(mso_bytes);

        let sig = issuer_kp.sign_prehashed(&digest);
        assert!(verify_ecdsa_prehashed(&issuer_kp.public_key, &digest, &sig));

        // Negatywny test: zmodyfikowana wiadomość
        let bad_digest = sha256_digest(b"Tampered-MSO-Payload");
        assert!(!verify_ecdsa_prehashed(&issuer_kp.public_key, &bad_digest, &sig));

        // Weryfikacja w warstwowym obwodzie kwadratowym nad F_p256
        let circuit = build_p256_ecdsa_curve_circuit();
        let witness = build_p256_ecdsa_curve_witness(&issuer_kp.public_key, &digest, &sig)
            .expect("Poprawny świadek ECDSA musi zostać wygenerowany");
        let evals = circuit.evaluate_all(&witness);
        let v_out = &evals[0];

        assert_eq!(v_out[0], Fp256::one());
        for gate_idx in 1..=5 {
            assert!(
                v_out[gate_idx].is_zero(),
                "Bramka ECDSA nr {} nie wyzerowała się dla poprawnego podpisu",
                gate_idx
            );
        }
    }
}
