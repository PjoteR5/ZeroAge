use ark_ff::Field;
use ark_std::rand::RngCore;
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

    /// Inicjalizuje Provera z dodatkowym losowym wierszem maskującym (One-Time Pad) na pozycji `m - 1`,
    /// zapewniającym pełną wiedzę zerową (ZK) podczas otwierania kombinacji liniowych wierszy.
    pub fn new_with_zk_blinding<R: RngCore>(
        witness: &[F],
        m: usize,
        k: usize,
        n: usize,
        rng: &mut R,
    ) -> Self {
        let matrix = EncodedMatrix::from_witness_with_blinding(witness, m, k, n, rng);
        let column_bytes: Vec<Vec<u8>> = (0..n).map(|c| matrix.serialize_column(c)).collect();
        let merkle_tree = MerkleTree::from_data_slices(&column_bytes);

        Self { matrix, merkle_tree }
    }

    /// Inicjalizuje Provera z gotowej zakodowanej macierzy `EncodedMatrix<F>`.
    pub fn from_encoded_matrix(matrix: EncodedMatrix<F>) -> Self {
        let n = matrix.n;
        let column_bytes: Vec<Vec<u8>> = (0..n).map(|c| matrix.serialize_column(c)).collect();
        let merkle_tree = MerkleTree::from_data_slices(&column_bytes);
        Self { matrix, merkle_tree }
    }

    /// Inicjalizuje Provera z pełnym maskowaniem wewnątrzwierszowym (`data_cols < k`) oraz
    /// wierszem maskującym o zerowej sumie na `0..data_cols` do dowodów iloczynu skalarnego Protokołu 2.5.
    pub fn new_full_zk<R: RngCore>(
        witness: &[F],
        m: usize,
        data_cols: usize,
        k: usize,
        n: usize,
        rng: &mut R,
    ) -> Self {
        let matrix = EncodedMatrix::from_witness_full_zk(witness, m, data_cols, k, n, rng);
        let column_bytes: Vec<Vec<u8>> = (0..n).map(|c| matrix.serialize_column(c)).collect();
        let merkle_tree = MerkleTree::from_data_slices(&column_bytes);

        Self { matrix, merkle_tree }
    }

    /// Oblicza wielomian dowodowy iloczynu skalarnego $P_{\text{dot}}(X)$ stopnia $< 2k - 1$ (ewaluowany na $0..n$):
    /// $P_{\text{dot}}(x) = W_{m-1}(x) + \sum_{i=0}^{m-2} A_i(x) \cdot W_i(x)$.
    pub fn prove_dot_product_constraint(
        &self,
        constraint_weights: &[F],
        data_cols_per_row: usize,
    ) -> Vec<F> {
        let m = self.matrix.m;
        let k = self.matrix.k;
        let n = self.matrix.n;
        let data_rows = m - 1;
        let encoder = crate::rs_code::ReedSolomonEncoder::<F>::new(k, n);

        let mut p_dot = self.matrix.get_row(m - 1).to_vec();
        for i in 0..data_rows {
            let mut a_row = vec![F::zero(); k];
            let start = i * data_cols_per_row;
            for j in 0..data_cols_per_row {
                if start + j < constraint_weights.len() {
                    a_row[j] = constraint_weights[start + j];
                }
            }
            let encoded_a = encoder.encode(&a_row);
            let w_row = self.matrix.get_row(i);
            for x in 0..n {
                p_dot[x] += encoded_a[x] * w_row[x];
            }
        }
        p_dot
    }
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
