use ark_ff::PrimeField;
use ark_std::rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::serialization::hex32;
use zkp_circuits::sha256::sha256_digest;
use zkp_core::field::Fp256;
use zkp_core::ligero::prover::LigeroProver;
use zkp_core::ligero::verifier::LigeroVerifier;
use zkp_core::merkle::MerkleProof;

const ATTR_COMMIT_DOMAIN: &[u8] = b"ZeroAge-MVP-AttrCommit-v1:";

/// Zobowiązanie kryptograficzne `SHA-256` do pojedynczego ukrytego atrybutu (np. daty urodzenia).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributeCommitment {
    /// 32-bajtowy skrót zobowiązania `SHA-256(domain || salt || attr_name || value_be)`
    #[serde(with = "hex32")]
    pub digest: [u8; 32],
}

impl AttributeCommitment {
    /// Tworzy zobowiązanie kryptograficzne dla atrybutu `attr_name` o wartości `value` przy użyciu soli `salt`.
    pub fn commit(attr_name: &str, value: u64, salt: &[u8; 16]) -> Self {
        let mut payload = Vec::with_capacity(ATTR_COMMIT_DOMAIN.len() + 16 + attr_name.len() + 8);
        payload.extend_from_slice(ATTR_COMMIT_DOMAIN);
        payload.extend_from_slice(salt);
        payload.extend_from_slice(attr_name.as_bytes());
        payload.extend_from_slice(&value.to_be_bytes());

        Self {
            digest: sha256_digest(&payload),
        }
    }

    /// Weryfikuje otwarcie zobowiązania (*opening*) – sprawdza, czy podana wartość `value` i `salt`
    /// odtwarzają dokładnie ten sam skrót `digest`.
    pub fn verify_opening(&self, attr_name: &str, value: u64, salt: &[u8; 16]) -> bool {
        let recomputed = Self::commit(attr_name, value, salt);
        self.digest == recomputed.digest
    }

    /// Reprezentuje 256-bitowy skrót zobowiązania jako kanoniczny element ciała $\mathbb{F}_{p_{256}}$
    /// (umożliwia bezpośrednie porównanie zobowiązania wewnątrz obwodu arytmetycznego ZKP).
    pub fn to_field_element(&self) -> Fp256 {
        Fp256::from_be_bytes_mod_order(&self.digest)
    }
}

/// Zobowiązanie wektorowe do rozszerzonego świadka obwodu ZKP oparte na schemacie **Ligero**
/// (macierz Reeda-Solomona + losowy wiersz maskujący ZK + drzewo Merkle'a `SHA-256`).
pub struct WitnessCommitment {
    pub rows_m: usize,
    pub cols_k: usize,
    pub code_n: usize,
    pub root: [u8; 32],
    prover: LigeroProver<Fp256>,
}

impl WitnessCommitment {
    /// Tworzy zaangażowanie (commitment) dla wektora świadka `witness` nad ciałem $\mathbb{F}_{p_{256}}$.
    pub fn commit_witness<R: RngCore>(
        witness: &[Fp256],
        rows_m: usize,
        cols_k: usize,
        code_n: usize,
        rng: &mut R,
    ) -> Self {
        let prover =
            LigeroProver::<Fp256>::new_with_zk_blinding(witness, rows_m, cols_k, code_n, rng);
        let root = prover.commitment();
        Self {
            rows_m,
            cols_k,
            code_n,
            root,
            prover,
        }
    }

    /// Generuje odpowiedź kombinacją liniową wierszy oraz otwiera wybrane kolumny ze ścieżkami Merkle'a.
    pub fn open_for_verifier(
        &self,
        row_weights: &[Fp256],
        queried_cols: &[usize],
    ) -> (Vec<Fp256>, Vec<(usize, Vec<Fp256>, MerkleProof)>) {
        let lin_comb = self.prover.answer_linear_combination(row_weights);
        let openings = self.prover.open_columns(queried_cols);
        (lin_comb, openings)
    }

    /// Weryfikuje po stronie Weryfikatora poprawność otwartych kolumn względem korzenia `root`
    /// oraz spójność kombinacji liniowej ze słowem kodowym Reeda-Solomona.
    pub fn verify_opening(
        root: &[u8; 32],
        rows_m: usize,
        cols_k: usize,
        code_n: usize,
        row_weights: &[Fp256],
        lin_comb: &[Fp256],
        openings: &[(usize, Vec<Fp256>, MerkleProof)],
    ) -> bool {
        let verifier = LigeroVerifier::<Fp256>::new(rows_m, cols_k, code_n);
        verifier.verify_openings(root, openings)
            && verifier.verify_linear_combination(lin_comb, row_weights, openings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;

    #[test]
    fn test_attribute_commitment_binding_and_hiding() {
        let salt_1 = [0x11u8; 16];
        let salt_2 = [0x22u8; 16];
        let dob_ts = 1_084_579_200u64; // 2004-05-15

        let c1 = AttributeCommitment::commit("birth_date", dob_ts, &salt_1);
        let c2 = AttributeCommitment::commit("birth_date", dob_ts, &salt_2);

        // Własność ukrywania (hiding): ta sama data z inną solą daje zupełnie inne zobowiązanie
        assert_ne!(c1.digest, c2.digest);

        // Poprawne otwarcie zobowiązania
        assert!(c1.verify_opening("birth_date", dob_ts, &salt_1));

        // Własność wiązania (binding): zmiana daty o 1 sekundę lub zmiana soli odrzuca otwarcie
        assert!(!c1.verify_opening("birth_date", dob_ts + 1, &salt_1));
        assert!(!c1.verify_opening("birth_date", dob_ts, &salt_2));
    }

    #[test]
    fn test_ligero_witness_vector_commitment_integration() {
        let mut rng = test_rng();
        let witness: Vec<Fp256> = (1..=12).map(|v| Fp256::from(v as u64)).collect();

        // 4 wiersze (3 wiersze danych po 4 elementy + 1 losowy wiersz maskujący ZK), kod RS 4 -> 12
        let comm = WitnessCommitment::commit_witness(&witness, 4, 4, 12, &mut rng);
        let weights = vec![
            Fp256::from(2u64),
            Fp256::from(5u64),
            Fp256::from(7u64),
            Fp256::from(1u64),
        ];
        let queried = vec![1, 5, 9];
        let (lin_comb, openings) = comm.open_for_verifier(&weights, &queried);

        assert!(WitnessCommitment::verify_opening(
            &comm.root,
            4,
            4,
            12,
            &weights,
            &lin_comb,
            &openings
        ));
    }
}
