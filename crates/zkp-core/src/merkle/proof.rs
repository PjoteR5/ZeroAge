use serde::{Deserialize, Serialize};
use crate::sha256::sha256;

/// Ścieżka uwierzytelniająca (Merkle Proof) dla pojedynczego liścia.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Indeks liścia w drzewie
    pub leaf_index: usize,
    /// Hasze rodzeństwa wzdłuż ścieżki od liścia do korzenia
    pub path: Vec<[u8; 32]>,
}

impl MerkleProof {
    pub fn new(leaf_index: usize, path: Vec<[u8; 32]>) -> Self {
        Self { leaf_index, path }
    }

    /// Weryfikuje, czy liść o danym skrócie leaf_hash należy do drzewa o korzeniu root.
    /// Złożoność czasowa: O(log n) haszowań SHA-256.
    pub fn verify(&self, root: &[u8; 32], leaf_hash: &[u8; 32]) -> bool {
        let mut current = *leaf_hash;
        let mut idx = self.leaf_index;

        for sibling in &self.path {
            let mut combined = [0u8; 64];
            if idx % 2 == 0 {
                // Liść jest lewym dzieckiem
                combined[..32].copy_from_slice(&current);
                combined[32..].copy_from_slice(sibling);
            } else {
                // Liść jest prawym dzieckiem
                combined[..32].copy_from_slice(sibling);
                combined[32..].copy_from_slice(&current);
            }
            current = sha256(&combined);
            idx /= 2;
        }

        &current == root
    }
}
