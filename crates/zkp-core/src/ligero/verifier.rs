use ark_ff::Field;
use crate::merkle::{MerkleProof, MerkleTree};
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
        let expected_depth = self.n.next_power_of_two().trailing_zeros() as usize;
        for (col_idx, col_vals, proof) in openings {
            if *col_idx >= self.n
                || *col_idx != proof.leaf_index
                || col_vals.len() != self.m
                || proof.path.len() != expected_depth
            {
                return false;
            }

            // Liczymy skrót kolumny z prefiksem liścia 0x00 (domain separation)
            let col_bytes = Self::serialize_column(col_vals);
            let leaf_hash = MerkleTree::hash_leaf(&col_bytes);

            // Sprawdzamy ścieżkę Merkle'a
            if !proof.verify(root, &leaf_hash) {
                return false;
            }
        }
        true
    }

    /// Weryfikuje w wiedzy zerowej kombinację ograniczeń liniowych $\langle \mathbf{a}, w' \rangle = b$
    /// na otwartych kolumnach z części parzystości `[k, n)`.
    ///
    /// - `constraint_weights`: spłaszczone wagi ograniczenia liniowego dla `(m - 1)` wierszy danych,
    /// - `expected_target`: oczekiwana suma iloczynu skalarnego $b$,
    /// - `dot_product_codeword`: wielomian iloczynu skalarnego $P_{\text{dot}}(X)$ stopnia $< 2k - 1$ (długość $n$),
    /// - `data_cols_per_row`: liczba kolumn danych $\ell \le k$ w każdym wierszu (pozostałe $k - \ell$ to maski ZK),
    /// - `openings`: otwarte kolumny z przedziału `[k, n)`.
    pub fn verify_dot_product_constraint(
        &self,
        constraint_weights: &[F],
        expected_target: F,
        dot_product_codeword: &[F],
        data_cols_per_row: usize,
        openings: &[(usize, Vec<F>, MerkleProof)],
    ) -> bool {
        if self.m < 2
            || data_cols_per_row == 0
            || data_cols_per_row > self.k
            || dot_product_codeword.len() != self.n
            || self.n < 2 * self.k - 1
        {
            return false;
        }

        // 1. Wszystkie otwierane kolumny MUSZĄ należeć do części parzystości [k, n),
        //    aby nigdy nie ujawnić surowych kolumn systematycznych [0, k).
        for (col_idx, col_vals, _) in openings {
            if *col_idx < self.k || *col_idx >= self.n || col_vals.len() != self.m {
                return false;
            }
        }

        // 2. Sprawdzenie niskiego stopnia (< 2k - 1) wielomianu P_dot
        let encoder_2k = ReedSolomonEncoder::<F>::new(2 * self.k - 1, self.n);
        if !encoder_2k.verify_codeword(dot_product_codeword) {
            return false;
        }

        // 3. Sprawdzenie, czy suma pierwszych `data_cols_per_row` ewaluacji daje oczekiwany cel `expected_target`
        let mut sum_on_data = F::zero();
        for j in 0..data_cols_per_row {
            sum_on_data += dot_product_codeword[j];
        }
        if sum_on_data != expected_target {
            return false;
        }

        // 4. Zakodowanie publicznych wierszy wag A_i(X) do długości n
        let data_rows = self.m - 1;
        let mut encoded_a_rows = Vec::with_capacity(data_rows);
        for r in 0..data_rows {
            let mut a_row = vec![F::zero(); self.k];
            let start = r * data_cols_per_row;
            for j in 0..data_cols_per_row {
                if start + j < constraint_weights.len() {
                    a_row[j] = constraint_weights[start + j];
                }
            }
            encoded_a_rows.push(self.encoder.encode(&a_row));
        }

        // 5. Sprawdzenie zgodności P_dot(c) == W_{m-1}(c) + sum_{i=0}^{m-2} A_i(c) * W_i(c) na otwartych kolumnach
        for (col_idx, col_vals, _) in openings {
            let c = *col_idx;
            let mut expected_c = col_vals[self.m - 1]; // wiersz maskujący iloczynu skalarnego
            for i in 0..data_rows {
                expected_c += encoded_a_rows[i][c] * col_vals[i];
            }
            if dot_product_codeword[c] != expected_c {
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
