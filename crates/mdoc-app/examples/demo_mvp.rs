//! `cargo run -p mdoc-app --example demo_mvp`

use ark_std::test_rng;

use mdoc_app::date_witness::CredentialDate;
use mdoc_app::issuer::{CredentialIssuer, SignedAgeCredential};
use mdoc_app::mvp_flow::{generate_mvp_age_proof, verify_mvp_age_proof_full, MvpAgeProof};
use mdoc_app::revocation::NonceReplayCache;

fn main() {
    println!("=========================================================================");
    println!(" ZeroAge (Model is_over18) — Emisja, JSON NIZK, Replay & Unieważnienia");
    println!("=========================================================================\n");

    let mut rng = test_rng();

    // 1. Emisja certyfikatu u Wystawcy
    let birth_date = CredentialDate::parse_iso("2004-05-15").unwrap();
    let valid_from = CredentialDate::parse_iso("2026-01-01").unwrap();
    let valid_until = CredentialDate::parse_iso("2027-01-01").unwrap();
    let verification_date = CredentialDate::parse_iso("2026-11-17").unwrap();

    println!("[1] Weryfikacja wieku u Wystawcy i emisja certyfikatu z flagą is_over18:");
    let mut issuer = CredentialIssuer::new("Urząd-Wydający-MVP", b"mvp-issuer-secret-seed");
    let credential = issuer
        .issue_age_credential("Jan Kowalski", birth_date, valid_from, valid_until)
        .expect("Błąd emisji poświadczenia");

    let cred_json = credential.to_json_pretty().expect("Błąd serializacji certyfikatu");
    let credential = SignedAgeCredential::from_json_str(&cred_json).expect("Błąd odczytu certyfikatu");

    println!("    -> ID certyfikatu: #{}", credential.credential_id);
    println!("    -> Flaga zapisana w certyfikacie (UKRYTA): is_over18 = {}", credential.private_witness.is_over18);
    println!("    -> Rozmiar certyfikatu JSON w portfelu: {} B", cred_json.len());

    // 2. Generowanie i serializacja dowodu ZKP do JSON
    println!("\n[2] Generowanie i serializacja paczki NIZK JSON Payload:");
    let challenge_nonce = [0x42u8; 16];
    let proof = generate_mvp_age_proof(&credential, verification_date, challenge_nonce, &mut rng)
        .expect("Błąd generowania dowodu ZKP");

    let proof_json = proof.to_json_pretty().expect("Błąd serializacji proof.json");
    println!("    -> Rozmiar przesyłanego pliku proof.json: {} B ({:.2} KB)", proof_json.len(), proof_json.len() as f64 / 1024.0);

    // 3. Weryfikacja po stronie Weryfikatora (z Replay Cache i Rejestrem Unieważnień)
    println!("\n[3] Weryfikacja paczki JSON przez Bramkę Weryfikatora:");
    let decoded_proof = MvpAgeProof::from_json_str(&proof_json).expect("Błąd odczytu proof.json");
    let mut replay_cache = NonceReplayCache::new();

    verify_mvp_age_proof_full(
        &decoded_proof,
        &issuer.public_key(),
        &issuer.revocation_registry,
        &mut replay_cache,
    )
    .expect("Błąd weryfikacji dowodu ZKP");
    println!("    -> 200 OK: Dowód ZKP poprawny! Potwierdzono certyfikat z flagą is_over18 = true.");

    // 4. Test Replay Attack
    let replay_res = verify_mvp_age_proof_full(
        &decoded_proof,
        &issuer.public_key(),
        &issuer.revocation_registry,
        &mut replay_cache,
    );
    println!("    -> Ponowne użycie tego samego proof.json (Replay Attack): {:?}", replay_res.unwrap_err());

    // 5. Test Rejestru Unieważnień
    println!("\n[4] Rejestr unieważnień (RevocationRegistry):");
    issuer.revoke_credential(
        credential.credential_id,
        verification_date,
        "Zgłoszona kradzież portfela",
    );
    let rev_json = issuer.revocation_registry.to_json_pretty().unwrap();
    println!("    -> Wpis w rejestrze unieważnień JSON:\n{}", rev_json);

    let fresh_proof = generate_mvp_age_proof(&credential, verification_date, [0x99u8; 16], &mut rng)
        .expect("Prover lokalnie generuje dowód");
    let rev_res = verify_mvp_age_proof_full(
        &fresh_proof,
        &issuer.public_key(),
        &issuer.revocation_registry,
        &mut replay_cache,
    );
    println!("    -> Próba autoryzacji unieważnionym certyfikatem: {:?}", rev_res.unwrap_err());
}
