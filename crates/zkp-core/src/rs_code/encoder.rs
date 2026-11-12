use ark_ff::{batch_inversion, Field};
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
    /// Spłaszczona macierz parzystości o wymiarach (n - k) x k dla punktów x in k..n
    parity_matrix: Vec<F>,
    _phantom: PhantomData<F>,
}

impl<F: Field> ReedSolomonEncoder<F> {
    pub fn new(k: usize, n: usize) -> Self {
        assert!(n >= k, "Długość słowa kodowego n ({}) musi być >= k ({})", n, k);

        let num_parity = n - k;
        let mut parity_matrix = Vec::with_capacity(num_parity * k);

        if k > 0 && num_parity > 0 {
            // Odwrotności liczb 1..(n-1) jednym batch_inversion
            let mut inv_ints: Vec<F> = (1..n).map(|i| F::from(i as u64)).collect();
            batch_inversion(&mut inv_ints);

            // Silnie 0..k do wag barycentrycznych w_j = (-1)^{k-1-j} / (j! * (k-1-j)!)
            let mut fact = Vec::with_capacity(k);
            fact.push(F::one());
            for j in 1..k {
                fact.push(fact[j - 1] * F::from(j as u64));
            }

            let mut w = Vec::with_capacity(k);
            for j in 0..k {
                let mut den = fact[j] * fact[k - 1 - j];
                if (k - 1 - j) % 2 == 1 {
                    den = -den;
                }
                w.push(den);
            }
            batch_inversion(&mut w);

            // Macierz Lagrange'a dla x in k..n: l_j(x) = (prod_{m=0}^{k-1} (x - m)) * w_j / (x - j)
            for x_idx in k..n {
                let mut phi_x = F::one();
                for m in 0..k {
                    phi_x *= F::from((x_idx - m) as u64);
                }
                for j in 0..k {
                    parity_matrix.push(phi_x * w[j] * inv_ints[x_idx - j - 1]);
                }
            }
        }

        Self {
            k,
            n,
            parity_matrix,
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

        if self.k == 0 {
            return vec![F::zero(); self.n];
        }

        let mut codeword = Vec::with_capacity(self.n);
        // Pierwsze k punktów: p(0), ..., p(k-1) to po prostu wejście
        codeword.extend_from_slice(msg);

        // Wyliczamy punkty k, k+1, ..., n-1 z prekomputowanej macierzy parzystości
        for row in self.parity_matrix.chunks_exact(self.k) {
            let mut eval = F::zero();
            for (&val, &coeff) in msg.iter().zip(row.iter()) {
                eval += val * coeff;
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
