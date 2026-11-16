//! Pakiet aplikacyjny `mdoc-app` – Warstwa poświadczeń **ISO 18013-5 (mDL / MDOC)**,
//! **Wystawca (`StateIssuer`)**, **Portfel Provera (`WalletProver`)** oraz
//! **Weryfikator Relying Party (`RelyingPartyVerifier`)** w oparciu o `SHA-256`, `ECDSA P-256` i `zkp-core`.

pub mod issuer;
pub mod mso;
pub mod presentation;

pub use issuer::{
    DeviceKeyAttestation, IssuedMdocCredential, StateIssuer, TrustedIssuerRegistry,
};
pub use mso::{DeviceKeyInfo, IssuerSignedItem, MobileSecurityObject, ValidityInfo};
pub use presentation::{
    MdocZkPresentationProof, RelyingPartyVerifier, VerifierChallenge, WalletProver,
};
