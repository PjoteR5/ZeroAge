use ark_ff::Field;
use crate::rs_code::ReedSolomonEncoder;

/// Macierz świadka Ligero o wymiarach m x n.
/// Świadek jest formatowany w m wierszy o długości k, a następnie każdy wiersz
/// jest rozszerzany kodem Reeda-Salomona do długości n.
#[derive(Clone, Debug)]
pub struct EncodedMatrix<F: Field> {
    pub m: usize,
    pub k: usize,
    pub n: usize,
    /// m wierszy, każdy o długości n
    pub rows: Vec<Vec<F>>,
}

impl<F: Field> EncodedMatrix<F> {
    /// Tworzy zakodowaną macierz na podstawie płaskiego wektora świadka.
    pub fn from_witness(witness: &[F], m: usize, k: usize, n: usize) -> Self {
        assert!(m * k >= witness.len(), "Wymiary m x k muszą pomieścić świadka");
        let encoder = ReedSolomonEncoder::<F>::new(k, n);

        let mut rows = Vec::with_capacity(m);
        for i in 0..m {
            let start = i * k;
            let mut row = Vec::with_capacity(k);
            for j in 0..k {
                let idx = start + j;
                if idx < witness.len() {
                    row.push(witness[idx]);
                } else {
                    row.push(F::zero()); // Padding zerami
                }
            }
            // Kodujemy wiersz kodem RS do długości n
            let encoded_row = encoder.encode(&row);
            rows.push(encoded_row);
        }

        Self { m, k, n, rows }
    }

    /// Pobiera wiersz macierzy o podanym indeksie (długość n)
    pub fn get_row(&self, row_idx: usize) -> &[F] {
        &self.rows[row_idx]
    }

    /// Pobiera całą kolumnę macierzy o podanym indeksie (długość m)
    pub fn get_column(&self, col_idx: usize) -> Vec<F> {
        assert!(col_idx < self.n, "Indeks kolumny poza zakresem");
        let mut col = Vec::with_capacity(self.m);
        for row in &self.rows {
            col.push(row[col_idx]);
        }
        col
    }

    /// Serializuje kolumnę do postaci binarnej (do haszowania w Drzewie Merkle'a)
    pub fn serialize_column(&self, col_idx: usize) -> Vec<u8> {
        let col = self.get_column(col_idx);
        let mut bytes = Vec::new();
        for val in col {
            val.serialize_compressed(&mut bytes).expect("Błąd serializacji elementu ciała");
        }
        bytes
    }

    /// Oblicza losową kombinację liniową wszystkich wierszy: v = sum_{i=0}^{m-1} weights[i] * row_i.
    /// Zwraca wektor o długości n.
    pub fn compute_linear_combination(&self, weights: &[F]) -> Vec<F> {
        assert_eq!(weights.len(), self.m, "Liczba wag musi być równa liczbie wierszy m");
        let mut res = vec![F::zero(); self.n];

        for (row_idx, row) in self.rows.iter().enumerate() {
            let w = weights[row_idx];
            for col_idx in 0..self.n {
                res[col_idx] += w * row[col_idx];
            }
        }

        res
    }
}
