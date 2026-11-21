//! Pakiet `zkp-circuits` – Obwody aplikacyjne ZKP dla systemu poświadczeń wieku (Frigo & shelat):
//! - `sha256`: Pełna funkcja skrótu FIPS 180-4 SHA-256 od podstaw + algebraiczne bramki `QuadGate` (`Ch`, `Maj`, `ROTR`, `SHR`).
//! - `ecdsa_p256`: Krzywa NIST P-256 (`secp256r1`), podpisy ECDSA P-256 z SHA-256 oraz obwód weryfikacji punktów (Algorytm 4).
//! - `age_circuit`: Obwód weryfikacji pełnoletności ($\text{wiek} \ge 18$), okna ważności MSO ($t_{\text{start}} \le t_{\text{now}} \le t_{\text{end}}$) i skrótu atrybutu.

pub mod age_circuit;
pub mod ecdsa_p256;
pub mod sha256;
