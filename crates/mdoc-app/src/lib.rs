//! Pakiet `mdoc-app` (Wersja MVP) — Emisja poświadczeń, schemat zobowiązań i reprezentacja dat:
//! - `commitment`: Schemat zobowiązań atrybutowych `SHA-256` (`AttributeCommitment`) oraz integracja ze zobowiązaniem wektorowym Ligero (`WitnessCommitment`).
//! - `date_witness`: Reprezentacja daty (`CredentialDate`) oraz rozdział na dane publiczne (`PublicAgeInputs`) i ukryte (`PrivateAgeWitness`).
//! - `issuer`: Wystawianie i podpisywanie poświadczeń wieku algorytmem ECDSA P-256 (`CredentialIssuer`, `SignedAgeCredential`).
//! - `mvp_flow`: Minimalny przepływ generowania i weryfikacji dowodu ZKP pełnoletności ($\text{wiek} \ge 18$).

pub mod commitment;
pub mod date_witness;
pub mod issuer;
pub mod mvp_flow;

pub use commitment::{AttributeCommitment, WitnessCommitment};
pub use date_witness::{
    default_min_age_18_seconds, CredentialDate, PrivateAgeWitness, PublicAgeInputs,
};
pub use issuer::{CredentialIssuer, SignedAgeCredential};
pub use mvp_flow::{generate_mvp_age_proof, verify_mvp_age_proof, MvpAgeProof};
