use ark_ff::Field;
use sha2::{Digest, Sha256};
use crate::merkle::MerkleProof;
use crate::rs_code::ReedSolomonEncoder;

/// Verifier protokołu Ligero (IOP / MPC-in-the-head).
pub struct LigeroVerifier<F: Field> {
    pub m: usize,
    pub k: usize,
    pub n: usize,
    pub encoder: ReedSolomonEncoder<F>,
}

impl<F: Field> LigeroVerifier<F> {
    pub fn new(m: usize, k: usize, n: usize) -> Self {
        let encoder = ReedSolomonEncoder::<F>::new(k, n);
        Self { m, k, n, encoder }
    }

    /// Pomocnicza funkcja serializująca elementy kolumny do haszowania w Merkle Tree.
    pub fn serialize_column(col_vals: &[F]) -> Vec<u8> {
        let mut bytes = Vec::new();
        for val in col_vals {
            val.serialize_compressed(&mut bytes).expect("Błąd serializacji elementu ciała");
        }
        bytes
    }

    /// Weryfikuje autentyczność otwartych kolumn względem korzenia Merkle'a (zaangażowania).
    pub fn verify_openings(
        &self,
        root: &[u8; 32],
        openings: &[(usize, Vec<F>, MerkleProof)],
    ) -> bool {
        for (col_idx, col_vals, proof) in openings {
            if *col_idx != proof.leaf_index || col_vals.len() != self.m {
                return false;
            }

            // Liczymy skrót kolumny
            let col_bytes = Self::serialize_column(col_vals);
            let mut hasher = Sha256::new();
            hasher.update(&col_bytes);
            let mut leaf_hash = [0u8; 32];
            leaf_hash.copy_from_slice(&hasher.finalize());

            // Sprawdzamy ścieżkę Merkle'a
            if !proof.verify(root, &leaf_hash) {
                return false;
            }
        }
        true
    }

    /// Weryfikuje spójność kombinacji liniowej wierszy podanej przez Provera:
    /// 1. Sprawdza, czy lin_comb jest poprawnym słowem kodowym Reeda-Salomona.
    /// 2. Sprawdza, czy lin_comb[c] == sum_{i=0}^{m-1} weights[i] * col_vals[i] dla każdej otwartej kolumny c.
    pub fn verify_linear_combination(
        &self,
        lin_comb: &[F],
        weights: &[F],
        openings: &[(usize, Vec<F>, MerkleProof)],
    ) -> bool {
        if lin_comb.len() != self.n || weights.len() != self.m {
            return false;
        }

        // 1. Sprawdzenie słowa kodowego Reeda-Salomona
        if !self.encoder.verify_codeword(lin_comb) {
            return false;
        }

        // 2. Sprawdzenie zgodności z otwartymi kolumnami
        for (col_idx, col_vals, _) in openings {
            let mut expected_val = F::zero();
            for i in 0..self.m {
                expected_val += weights[i] * col_vals[i];
            }

            if lin_comb[*col_idx] != expected_val {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ligero::prover::LigeroProver;
    use ark_ff::{Fp64, MontBackend, MontConfig};

    #[derive(MontConfig)]
    #[modulus = "17"]
    #[generator = "3"]
    pub struct FqConfig;
    pub type F17 = Fp64<MontBackend<FqConfig, 1>>;

    #[test]
    fn test_ligero_full_protocol_flow() {
        // Świadek: 6 liczb w ciele F_17
        let witness = vec![
            F17::from(1u64), F17::from(2u64), F17::from(3u64),
            F17::from(4u64), F17::from(5u64), F17::from(6u64),
        ];

        // Parametry macierzy: m = 2 wiersze, k = 3 kolumny (2 x 3 = 6 elementów)
        // Rozszerzenie kodem RS do n = 6 kolumn
        let m = 2;
        let k = 3;
        let n = 6;

        // 1. KROK PROVERA: Commit
        let prover = LigeroProver::<F17>::new(&witness, m, k, n);
        let root = prover.commitment();

        // 2. KROK VERIFIERA: Losowe wyzwanie wag dla wierszy
        let weights = vec![F17::from(3u64), F17::from(5u64)];
        let verifier = LigeroVerifier::<F17>::new(m, k, n);

        // 3. KROK PROVERA: Odpowiedź kombinacją liniową
        let lin_comb = prover.answer_linear_combination(&weights);

        // 4. KROK VERIFIERA: Losowe zapytanie o kolumny (np. kolumny 1 i 4)
        let queried_cols = vec![1, 4];
        let openings = prover.open_columns(&queried_cols);

        // 5. WERYFIKACJA 1: Poprawność ścieżek Merkle'a
        assert!(verifier.verify_openings(&root, &openings));

        // 6. WERYFIKACJA 2: Poprawność słowa kodowego i spójność kombinacji liniowej
        assert!(verifier.verify_linear_combination(&lin_comb, &weights, &openings));

        // Test negatywny: sfałszowana wartość w kombinacji liniowej
        let mut fake_lin_comb = lin_comb.clone();
        fake_lin_comb[1] += F17::from(1u64);
        assert!(!verifier.verify_linear_combination(&fake_lin_comb, &weights, &openings));
    }
}
