//! `cargo run -p mdoc-app --example demo_mvp`

use ark_std::test_rng;

use mdoc_app::date_witness::CredentialDate;
use mdoc_app::issuer::CredentialIssuer;
use mdoc_app::mvp_flow::{generate_mvp_age_proof, verify_mvp_age_proof};

fn main() {
    println!("=========================================================================");
    println!(" ZeroAge (Gałąź MVP) — Emisja Poświadczeń, Zobowiązania i Dowód ZKP 18+");
    println!("=========================================================================\n");

    let mut rng = test_rng();

    // 1. Przygotowanie reprezentacji dat (urodzenia, ważności poświadczenia oraz weryfikacji)
    let birth_date = CredentialDate::parse_iso("2004-05-15").unwrap();
    let valid_from = CredentialDate::parse_iso("2026-01-01").unwrap();
    let valid_until = CredentialDate::parse_iso("2027-01-01").unwrap();
    let verification_date = CredentialDate::parse_iso("2026-11-17").unwrap();

    println!("[1] Reprezentacja daty (date_witness.rs):");
    println!(
        "    -> Data urodzenia (UKRYTA): {} (timestamp: {} s)",
        birth_date.to_iso_string(),
        birth_date.to_timestamp_seconds()
    );
    println!(
        "    -> Data weryfikacji (PUBLICZNA): {} (timestamp: {} s)",
        verification_date.to_iso_string(),
        verification_date.to_timestamp_seconds()
    );

    // 2. Wystawianie i podpisywanie poświadczenia przez Wystawcę (issuer.rs + commitment.rs)
    println!("\n[2] Emisja i podpisanie poświadczenia przez Wystawcę (issuer.rs):");
    let mut issuer = CredentialIssuer::new("Urząd-Wydający-MVP", b"mvp-issuer-secret-seed");
    let credential = issuer
        .issue_age_credential("Jan Kowalski", birth_date, valid_from, valid_until)
        .expect("Błąd emisji poświadczenia");

    println!("    -> ID poświadczenia: #{}", credential.credential_id);
    println!(
        "    -> Zobowiązanie SHA-256 do daty urodzenia (PUBLICZNE): {:02x?}...",
        &credential.dob_commitment.digest[..8]
    );
    println!(
        "    -> Tajna sól zobowiązania (UKRYTA w portfelu): {:02x?}...",
        &credential.private_witness.secret_salt[..4]
    );
    println!(
        "    -> Weryfikacja podpisu ECDSA P-256 Wystawcy: {}",
        credential.verify_issuer_signature()
    );

    // 3. Generowanie i weryfikacja dowodu ZKP (mvp_flow.rs)
    println!("\n[3] Generowanie i weryfikacja dowodu ZKP (wiek >= 18 bez ujawniania daty urodzenia):");
    let challenge_nonce = [0x42u8; 16];
    let proof = generate_mvp_age_proof(&credential, verification_date, challenge_nonce, &mut rng)
        .expect("Błąd generowania dowodu ZKP");

    verify_mvp_age_proof(&proof, &issuer.public_key())
        .expect("Błąd weryfikacji dowodu ZKP");

    println!(
        "    -> Zaangażowanie wektorowe świadka (Ligero Merkle Root): {:02x?}...",
        &proof.ligero_root[..8]
    );
    println!("    -> WYNIK: Dowód ZKP poprawny! Potwierdzono wiek >= 18 bez ujawnienia daty 2004-05-15.");
}
