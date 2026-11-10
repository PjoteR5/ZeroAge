use ark_ff::Field;
use std::marker::PhantomData;

/// Koder i weryfikator kodów Reeda-Salomona nad ciałami pierwszymi (Zgodny z Rozdziałem 3.1 ZKP.pdf).
/// Wiadomość o długości k jest interpretowana jako ewaluacje wielomianu stopnia < k w punktach {0, 1, ..., k-1}.
/// Słowo kodowe o długości n to ewaluacje w punktach {0, 1, ..., n-1}.
#[derive(Clone, Debug)]
pub struct ReedSolomonEncoder<F: Field> {
    /// Długość wektora wiadomości (stopień wielomianu < k)
    pub k: usize,
    /// Długość słowa kodowego po rozszerzeniu (n > k)
    pub n: usize,
    _phantom: PhantomData<F>,
}

impl<F: Field> ReedSolomonEncoder<F> {
    pub fn new(k: usize, n: usize) -> Self {
        assert!(n >= k, "Długość słowa kodowego n ({}) musi być >= k ({})", n, k);
        Self {
            k,
            n,
            _phantom: PhantomData,
        }
    }

    /// Oblicza bazę Lagrange'a l_j(x) = prod_{m != j} (x - m) / (j - m) dla punktów {0, 1, ..., k-1}.
    pub fn lagrange_basis(k: usize, j: usize, x: F) -> F {
        let mut num = F::one();
        let mut den = F::one();
        let j_f = F::from(j as u64);

        for m in 0..k {
            if m != j {
                let m_f = F::from(m as u64);
                num *= x - m_f;
                den *= j_f - m_f;
            }
        }

        num * den.inverse().expect("Mianownik bazy Lagrange'a nie może być zerem")
    }

    /// Koduje wiadomość o długości k do słowa kodowego o długości n.
    /// Pierwsze k elementów to oryginalna wiadomość (kod systematyczny).
    /// Elementy k..n to wartości wielomianu w punktach k, k+1, ..., n-1.
    pub fn encode(&self, msg: &[F]) -> Vec<F> {
        assert_eq!(
            msg.len(),
            self.k,
            "Długość wiadomości ({}) musi być równa k ({})",
            msg.len(),
            self.k
        );

        let mut codeword = Vec::with_capacity(self.n);
        // Pierwsze k punktów: p(0), ..., p(k-1) to po prostu wejście
        codeword.extend_from_slice(msg);

        // Wyliczamy punkty k, k+1, ..., n-1 za pomocą interpolacji Lagrange'a
        for x_idx in self.k..self.n {
            let x_f = F::from(x_idx as u64);
            let mut eval = F::zero();
            for (j, &val) in msg.iter().enumerate() {
                eval += val * Self::lagrange_basis(self.k, j, x_f);
            }
            codeword.push(eval);
        }

        codeword
    }

    /// Sprawdza, czy wektor o długości n jest poprawnym słowem kodowym Reeda-Salomona.
    /// Wykorzystywane przez Verifiera Ligero przy sprawdzaniu losowych kombinacji liniowych wierszy.
    pub fn verify_codeword(&self, codeword: &[F]) -> bool {
        if codeword.len() != self.n {
            return false;
        }

        let msg = &codeword[0..self.k];
        let expected = self.encode(msg);
        codeword == expected.as_slice()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{Fp64, MontBackend, MontConfig};

    #[derive(MontConfig)]
    #[modulus = "17"]
    #[generator = "3"]
    pub struct FqConfig;
    pub type F17 = Fp64<MontBackend<FqConfig, 1>>;

    #[test]
    fn test_reed_solomon_encoding() {
        // Wielomian stopnia 2 (k = 3): p(X) = 2*X^2 + 3*X + 5 mod 17
        // p(0) = 5
        // p(1) = 10
        // p(2) = 2
        let msg = vec![F17::from(5u64), F17::from(10u64), F17::from(2u64)];
        let encoder = ReedSolomonEncoder::<F17>::new(3, 6); // k=3, n=6

        let codeword = encoder.encode(&msg);
        assert_eq!(codeword.len(), 6);

        // Sprawdzamy punkty systematyczne:
        assert_eq!(codeword[0], F17::from(5u64));
        assert_eq!(codeword[1], F17::from(10u64));
        assert_eq!(codeword[2], F17::from(2u64));

        // Sprawdzamy rozszerzone punkty:
        // p(3) = 2*9 + 3*3 + 5 = 32 = 15 mod 17
        assert_eq!(codeword[3], F17::from(15u64));
        // p(4) = 2*16 + 3*4 + 5 = 32 + 12 + 5 = 49 = 15 mod 17
        assert_eq!(codeword[4], F17::from(15u64));
        // p(5) = 2*25 + 3*5 + 5 = 50 + 15 + 5 = 70 = 2 mod 17
        assert_eq!(codeword[5], F17::from(2u64));

        // Weryfikacja słowa kodowego:
        assert!(encoder.verify_codeword(&codeword));

        // Test negatywny: sfałszowany 1 element w słowie kodowym
        let mut tampered = codeword.clone();
        tampered[4] = F17::from(0u64);
        assert!(!encoder.verify_codeword(&tampered));
    }
}
