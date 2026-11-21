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
    ///
    /// Uwaga bezpieczeństwa:
    /// - Węzły wewnętrzne używają prefiksu separacji domen `0x01` (RFC 6962),
    /// - Wymagane jest `idx == 0` po przejściu całej ścieżki (blokuje fałszowanie indeksu poza zakres).
    pub fn verify(&self, root: &[u8; 32], leaf_hash: &[u8; 32]) -> bool {
        let mut current = *leaf_hash;
        let mut idx = self.leaf_index;

        for sibling in &self.path {
            let mut combined = [0u8; 65];
            combined[0] = 0x01; // Prefiks węzła wewnętrznego (domain separation)
            if idx % 2 == 0 {
                // Liść jest lewym dzieckiem
                combined[1..33].copy_from_slice(&current);
                combined[33..].copy_from_slice(sibling);
            } else {
                // Liść jest prawym dzieckiem
                combined[1..33].copy_from_slice(sibling);
                combined[33..].copy_from_slice(&current);
            }
            current = sha256(&combined);
            idx /= 2;
        }

        idx == 0 && &current == root
    }
}
