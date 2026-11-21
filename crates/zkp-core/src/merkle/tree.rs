use crate::merkle::proof::MerkleProof;
use crate::sha256::sha256;

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
                let mut combined = [0u8; 65];
                combined[0] = 0x01; // Prefiks węzła wewnętrznego (domain separation)
                combined[1..33].copy_from_slice(&chunk[0]);
                combined[33..].copy_from_slice(&chunk[1]);
                next_layer.push(sha256(&combined));
            }

            layers.push(next_layer);
        }

        Self { num_leaves, layers }
    }

    /// Haszuje surowe bajty liścia z prefiksem separacji domen `0x00` (RFC 6962).
    pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(1 + data.len());
        buf.push(0x00);
        buf.extend_from_slice(data);
        sha256(&buf)
    }

    /// Tworzy Drzewo Merkle'a bezpośrednio z surowych bajtów danych (np. kolumn macierzy Ligero).
    /// Każdy ciąg bajtów jest najpierw haszowany do liścia za pomocą SHA-256 z prefiksem `0x00`.
    pub fn from_data_slices<T: AsRef<[u8]>>(data: &[T]) -> Self {
        let leaves: Vec<[u8; 32]> = data.iter().map(|d| Self::hash_leaf(d.as_ref())).collect();

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
        let leaf2_hash = MerkleTree::hash_leaf(col2);

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
