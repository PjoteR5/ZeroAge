#![allow(non_local_definitions)]

use ark_ff::{Field, Fp256 as ArkFp256, Fp64, MontBackend, MontConfig};

/// Ciało pierwsze NIST P-256 ($\mathbb{F}_{p_{256}}$) – ciało bazowe krzywej eliptycznej secp256r1:
/// $p_{256} = 2^{256} - 2^{224} + 2^{192} + 2^{96} - 1$
/// $= 115792089210356248762697446949407573530086143415290314195533631308867097853951$.
///
/// Zgodnie z artykułem Frigo & shelat (*Anonymous Credentials from ECDSA*), bezpośrednie użycie
/// ciała bazowego krzywej P-256 eliminuje narzut arytmetyki obcego ciała przy weryfikacji podpisu ECDSA.
#[derive(MontConfig)]
#[modulus = "115792089210356248762697446949407573530086143415290314195533631308867097853951"]
#[generator = "3"]
pub struct P256BaseConfig;

/// Typ elementu ciała bazowego NIST P-256 ($\mathbb{F}_{p_{256}}$) w reprezentacji Montgomery'ego (4 × 64-bit).
pub type Fp256 = ArkFp256<MontBackend<P256BaseConfig, 4>>;

/// Ciało referencyjne 64-bitowe Goldilocks ($p_{64} = 2^{64} - 2^{32} + 1$) do szybkich testów i benchmarków.
#[derive(MontConfig)]
#[modulus = "18446744069414584321"]
#[generator = "7"]
pub struct Fq64Config;

/// Typ elementu 64-bitowego ciała referencyjnego $\mathbb{F}_{p_{64}}$.
pub type F64 = Fp64<MontBackend<Fq64Config, 1>>;

/// Rozkłada 32-bitowe słowo `u32` (np. rejestr stanu SHA-256) na 32 elementy ciała `{0, 1}`
/// w kolejności od bitu najstarszego (MSB-first, zgodnie ze standardem FIPS 180-4 SHA-256).
pub fn u32_to_field_bits_be<F: Field>(val: u32) -> [F; 32] {
    let mut bits = [F::zero(); 32];
    for i in 0..32 {
        if ((val >> (31 - i)) & 1) == 1 {
            bits[i] = F::one();
        }
    }
    bits
}

/// Rekonstruuje 32-bitowe słowo `u32` z tablicy 32 bitów zapisanych jako elementy ciała `{0, 1}` (MSB-first).
pub fn field_bits_be_to_u32<F: Field>(bits: &[F; 32]) -> u32 {
    let mut val = 0u32;
    for i in 0..32 {
        if bits[i] == F::one() {
            val |= 1u32 << (31 - i);
        } else {
            debug_assert!(
                bits[i].is_zero(),
                "Przewód bitowy musi przyjmować wartość 0 lub 1"
            );
        }
    }
    val
}

/// Rozkłada 64-bitową liczbę całkowitą `u64` (np. znacznik czasu `t_now` lub `dob`)
/// na 64 elementy ciała `{0, 1}` w kolejności LSB-first ($b_0 + 2 b_1 + \dots + 2^{63} b_{63}$).
pub fn u64_to_field_bits_le<F: Field>(val: u64) -> [F; 64] {
    let mut bits = [F::zero(); 64];
    for i in 0..64 {
        if ((val >> i) & 1) == 1 {
            bits[i] = F::one();
        }
    }
    bits
}

/// Pakuje plaster bitów `bool` (LSB-first) w pojedynczy element ciała $\sum_{i} b_i \cdot 2^i$.
pub fn pack_bits_to_field<F: Field>(bits: &[bool]) -> F {
    let two = F::from(2u64);
    let mut power = F::one();
    let mut acc = F::zero();
    for &b in bits {
        if b {
            acc += power;
        }
        power *= two;
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{Field, One, Zero};

    #[test]
    fn test_fp256_field_identities() {
        let a = Fp256::from(1234567890123456789u64);
        let b = Fp256::from(9876543210987654321u64);
        let prod = a * b;
        let inv_b = b.inverse().expect("Niezerowy element w F_p256 musi być odwracalny");
        assert_eq!(prod * inv_b, a);
        assert_eq!(Fp256::zero() + Fp256::one(), Fp256::one());
    }

    #[test]
    fn test_u32_bit_conversion_roundtrip() {
        let sample: u32 = 0x6a09e667; // Stała początkowa H0[0] w SHA-256
        let field_bits = u32_to_field_bits_be::<Fp256>(sample);
        let recovered = field_bits_be_to_u32(&field_bits);
        assert_eq!(sample, recovered);
    }

    #[test]
    fn test_bit_packing() {
        // 1 + 0*2 + 1*4 + 1*8 = 13
        let packed: Fp256 = pack_bits_to_field(&[true, false, true, true]);
        assert_eq!(packed, Fp256::from(13u64));
    }
}
