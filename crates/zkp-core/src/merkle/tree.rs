use sha2::{Digest, Sha256};
use crate::merkle::proof::MerkleProof;

/// Binarne drzewo skrótów (Drzewo Merkle'a) zaimplementowane od zera na bazie SHA-256.
/// Wykorzystywane w Ligero do zaangażowania zakodowanych kolumn świadka.
#[derive(Clone, Debug)]
pub struct MerkleTree {
    /// Liczba oryginalnych liści
    pub num_leaves: usize,
    /// Warstwy drzewa: layers[0] to liście, layers.last() to korzeń o długości 1
    pub layers: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    /// Buduje Drzewo Merkle'a z gotowych 32-bajtowych skrótów liści.
    pub fn new(mut leaves: Vec<[u8; 32]>) -> Self {
        assert!(!leaves.is_empty(), "Drzewo Merkle'a nie może być puste");
        let num_leaves = leaves.len();

        // Uzupełniamy liczbę liści do potęgi 2 (duplikując ostatni liść)
        let next_pow2 = num_leaves.next_power_of_two();
        if next_pow2 > leaves.len() {
            let last = *leaves.last().unwrap();
            leaves.resize(next_pow2, last);
        }

        let mut layers = Vec::new();
        layers.push(leaves);

        // Budujemy kolejne warstwy aż do pojedynczego korzenia
        while layers.last().unwrap().len() > 1 {
            let prev_layer = layers.last().unwrap();
            let mut next_layer = Vec::with_capacity(prev_layer.len() / 2);

            for chunk in prev_layer.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(&chunk[0]);
                hasher.update(&chunk[1]);
                let res = hasher.finalize();
                let mut node = [0u8; 32];
                node.copy_from_slice(&res);
                next_layer.push(node);
            }

            layers.push(next_layer);
        }

        Self { num_leaves, layers }
    }

    /// Tworzy Drzewo Merkle'a bezpośrednio z surowych bajtów danych (np. kolumn macierzy Ligero).
    /// Każdy ciąg bajtów jest najpierw haszowany do liścia za pomocą SHA-256.
    pub fn from_data_slices<T: AsRef<[u8]>>(data: &[T]) -> Self {
        let leaves: Vec<[u8; 32]> = data
            .iter()
            .map(|d| {
                let mut hasher = Sha256::new();
                hasher.update(d.as_ref());
                let res = hasher.finalize();
                let mut leaf = [0u8; 32];
                leaf.copy_from_slice(&res);
                leaf
            })
            .collect();

        Self::new(leaves)
    }

    /// Zwraca 32-bajtowy korzeń Drzewa Merkle'a (zaangażowanie / commitment).
    pub fn root(&self) -> [u8; 32] {
        self.layers.last().unwrap()[0]
    }

    /// Generuje dowód Merkle'a (ścieżkę uwierzytelniającą) dla liścia o podanym indeksie.
    pub fn generate_proof(&self, leaf_index: usize) -> MerkleProof {
        assert!(leaf_index < self.num_leaves, "Indeks liścia poza zakresem");
        let mut path = Vec::with_capacity(self.layers.len() - 1);
        let mut idx = leaf_index;

        // Przechodzimy od warstwy liści w górę aż do warstwy pod korzeniem
        for layer in &self.layers[0..self.layers.len() - 1] {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            path.push(layer[sibling_idx]);
            idx /= 2;
        }

        MerkleProof::new(leaf_index, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_build_and_verify() {
        // Tworzymy 4 przykładowe kolumny danych Ligero
        let col0 = b"col0_data_elements";
        let col1 = b"col1_data_elements";
        let col2 = b"col2_data_elements";
        let col3 = b"col3_data_elements";

        let tree = MerkleTree::from_data_slices(&[col0, col1, col2, col3]);
        let root = tree.root();

        // Sprawdzamy dowód dla kolumny 2
        let leaf2_hash = {
            let mut hasher = Sha256::new();
            hasher.update(col2);
            let mut h = [0u8; 32];
            h.copy_from_slice(&hasher.finalize());
            h
        };

        let proof2 = tree.generate_proof(2);
        assert_eq!(proof2.leaf_index, 2);
        assert!(proof2.verify(&root, &leaf2_hash));

        // Test negatywny: sfałszowany liść
        let fake_leaf = [99u8; 32];
        assert!(!proof2.verify(&root, &fake_leaf));

        // Test negatywny: sfałszowany korzeń
        let fake_root = [11u8; 32];
        assert!(!proof2.verify(&fake_root, &leaf2_hash));
    }
}
