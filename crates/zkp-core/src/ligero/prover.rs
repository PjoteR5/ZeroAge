use ark_ff::Field;
use crate::ligero::matrix::EncodedMatrix;
use crate::merkle::{MerkleProof, MerkleTree};

/// Prover protokołu Ligero (IOP / MPC-in-the-head).
pub struct LigeroProver<F: Field> {
    pub matrix: EncodedMatrix<F>,
    pub merkle_tree: MerkleTree,
}

impl<F: Field> LigeroProver<F> {
    /// Inicjalizuje Provera: układa świadka w macierz, koduje wiersze kodem RS i buduje Drzewo Merkle'a nad kolumnami.
    pub fn new(witness: &[F], m: usize, k: usize, n: usize) -> Self {
        let matrix = EncodedMatrix::from_witness(witness, m, k, n);

        // Serializujemy każdą z n kolumn do bajtów i tworzymy z nich liście drzewa Merkle'a
        let column_bytes: Vec<Vec<u8>> = (0..n).map(|c| matrix.serialize_column(c)).collect();
        let merkle_tree = MerkleTree::from_data_slices(&column_bytes);

        Self { matrix, merkle_tree }
    }

    /// Zwraca zaangażowanie (commitment) świadka: korzeń Drzewa Merkle'a nad kolumnami.
    pub fn commitment(&self) -> [u8; 32] {
        self.merkle_tree.root()
    }

    /// Odpowiada na losowe wyzwanie weryfikatora, wyliczając kombinację liniową wierszy macierzy.
    pub fn answer_linear_combination(&self, weights: &[F]) -> Vec<F> {
        self.matrix.compute_linear_combination(weights)
    }

    /// Otwiera wybrane t kolumn: zwraca indeksy, wartości elementów w kolumnie oraz ścieżki Merkle'a.
    pub fn open_columns(&self, queried_cols: &[usize]) -> Vec<(usize, Vec<F>, MerkleProof)> {
        queried_cols
            .iter()
            .map(|&c| {
                let col_vals = self.matrix.get_column(c);
                let proof = self.merkle_tree.generate_proof(c);
                (c, col_vals, proof)
            })
            .collect()
    }
}
