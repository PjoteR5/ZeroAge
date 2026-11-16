//! Demonstracja pełnego przepływu systemu ZeroAge (ISO 18013-5 MDOC + SHA-256 + ECDSA P-256 + Protokół 2.5):
//! `cargo run -p mdoc-app --example demo_mdoc_flow`

use std::time::Instant;
use ark_std::test_rng;

use mdoc_app::issuer::{DeviceKeyAttestation, StateIssuer};
use mdoc_app::presentation::{RelyingPartyVerifier, WalletProver};
use zkp_circuits::ecdsa_p256::EcdsaKeyPair;

fn main() {
    println!("==========================================================================");
    println!(" ZeroAge Rust ZKP — Anonymous Credentials from ECDSA (ISO 18013-5 / SHA-256)");
    println!(" Architektura: StateIssuer (ECDSA P-256 + CBOR MSO) -> WalletProver -> Verifier");
    println!("==========================================================================\n");

    let mut rng = test_rng();
    let t_now: u64 = 1_794_064_800; // 2026-11-07 UTC

    // 1. Inicjalizacja Wystawcy (Urząd) oraz Klucza Urządzenia (Secure Element)
    println!("[1] Inicjalizacja Państwowego Wystawcy (NIST P-256) oraz Portfela Urządzenia...");
    let mut issuer = StateIssuer::new("PL-Ministerstwo-Cyfryzacji-mObywatel", b"gov-master-key-seed");
    let device_kp = EcdsaKeyPair::from_seed(b"user-iphone-secure-enclave-seed");
    let attestation = DeviceKeyAttestation::create(&device_kp, b"device-enrollment-nonce");

    // 2. Wydanie poświadczenia MSO w formacie CBOR ze skrótami SHA-256
    let dob_adult = t_now - (21 * 365 + 5) * 86_400; // 21 lat
    let t_issue = Instant::now();
    let credential = issuer
        .issue_credential(
            "Jan Kowalski",
            dob_adult,
            t_now,
            t_now - 3600,
            t_now + 86_400 * 365,
            &attestation,
        )
        .expect("Wydanie poświadczenia MSO nie powiodło się");
    let issue_elapsed = t_issue.elapsed();

    println!(
        "    -> Wydano poświadczenie MSO ID #{} (rozmiar CBOR: {} bajtów, czas: {:.2?})",
        credential.credential_id,
        credential.mso_cbor_bytes.len(),
        issue_elapsed
    );
    println!(
        "    -> Algorytm skrótu MSO: {}, liczba valueDigests: {}",
        credential.mso.digest_algorithm,
        credential.mso.value_digests.len()
    );

    // 3. Generowanie i weryfikacja dowodu ZKP (Protokół 2.5: Sumcheck + OTP + Ligero)
    println!("\n[2] Generowanie nieinteraktywnego dowodu ZKP (wiek >= 18) dla 'adult-portal.pl'...");
    let mut verifier = RelyingPartyVerifier::new(issuer.export_registry());
    let challenge = verifier.issue_challenge("sess-demo-001", "adult-portal.pl", t_now, &mut rng);

    let t_prove = Instant::now();
    let proof = WalletProver::prove_age_over_18(&credential, &device_kp, &challenge, &mut rng)
        .expect("Generowanie dowodu ZKP nie powiodło się");
    let prove_elapsed = t_prove.elapsed();

    let t_verify = Instant::now();
    verifier
        .verify_presentation(&challenge, &proof)
        .expect("Weryfikacja dowodu ZKP nie powiodła się");
    let verify_elapsed = t_verify.elapsed();

    println!("    -> Dowód ZKP wygenerowany w: {:.2?}", prove_elapsed);
    println!("    -> Dowód ZKP zweryfikowany w: {:.2?}", verify_elapsed);
    println!(
        "    -> Korzeń zobowiązania Ligero (SHA-256): {:02x?}...",
        &proof.ligero_root[..8]
    );
    println!(
        "    -> Rundy zamaskowanego Sumchecka: {}, otwarte kolumny Ligero: {}",
        proof.masked_transcript.rounds.len(),
        proof.ligero_openings.len()
    );
    println!("    -> STATUS: DOSTĘP 18+ PRZYZNANY (0 ujawnionych danych osobowych!)\n");

    // 4. Symulacja ataków bezpieczeństwa
    println!("[3] Testy odporności na ataki kryptograficzne:");
    let replay_res = verifier.verify_presentation(&challenge, &proof);
    println!(
        "    -> Test 1 (Atak Replay tym samym dowodem): {:?}",
        replay_res.unwrap_err()
    );

    let dob_17yo = t_now - (17 * 365) * 86_400;
    let minor_cred = issuer
        .issue_credential(
            "Niepełnoletni 17-latek",
            dob_17yo,
            t_now,
            t_now - 3600,
            t_now + 86_400 * 365,
            &attestation,
        )
        .unwrap();
    let chal_minor = verifier.issue_challenge("sess-demo-002", "adult-portal.pl", t_now, &mut rng);
    let minor_res = WalletProver::prove_age_over_18(&minor_cred, &device_kp, &chal_minor, &mut rng);
    println!(
        "    -> Test 2 (Atak niedomiaru 17-latka w F_p256): {:?}",
        minor_res.unwrap_err()
    );

    issuer.revoke_credential(credential.credential_id);
    let verifier_after_revoke = RelyingPartyVerifier::new(issuer.export_registry());
    let chal_rev =
        verifier_after_revoke.issue_challenge("sess-demo-003", "adult-portal.pl", t_now, &mut rng);
    let rev_res = WalletProver::prove_age_over_18(&credential, &device_kp, &chal_rev, &mut rng);
    println!(
        "    -> Test 3 (Użycie odwołanego poświadczenia MSO): {:?}",
        rev_res.unwrap_err()
    );

    println!("\n=== Wszystkie etapy demonstracji zakończone sukcesem! ===");
}
