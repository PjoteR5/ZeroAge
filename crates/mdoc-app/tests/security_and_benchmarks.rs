use ark_ff::One;
use ark_std::test_rng;
use std::time::Instant;

use mdoc_app::date_witness::CredentialDate;
use mdoc_app::issuer::CredentialIssuer;
use mdoc_app::mvp_flow::{
    generate_mvp_age_proof, verify_mvp_age_proof, verify_mvp_age_proof_full, MvpAgeProof,
};
use mdoc_app::revocation::NonceReplayCache;
use zkp_circuits::age_circuit::{
    build_age_and_validity_circuit, build_age_and_validity_witness, is_age_circuit_output_satisfied,
};
use zkp_circuits::ecdsa_p256::{
    build_p256_ecdsa_curve_circuit, build_p256_ecdsa_curve_witness, EcdsaKeyPair,
};
use zkp_circuits::sha256::{
    build_sha256_round_nonlinear_circuit, build_sha256_round_witness, ch, maj, sha256_digest,
    SHA256_H0,
};
use zkp_core::circuit::{CircuitLayer, LayeredCircuit, QuadGate, QuadTerm};
use zkp_core::field::{u32_to_field_bits_be, Fp256};
use zkp_core::protocol25::{Protocol25Params, Protocol25Prover, Protocol25Verifier};
use zkp_core::transcript::FiatShamirTranscript;

// ===========================================================================
// ZGODNOŚĆ Z ARTYKUŁEM FRIGO & SHELAT (Sekcje 4.1 i 4.2 w pełnym ZKP)
// ===========================================================================

#[test]
fn test_paper_compliance_ecdsa_p256_algorithm4_in_protocol25() {
    let mut rng = test_rng();
    let kp = EcdsaKeyPair::from_seed(b"Paper-Compliance-ECDSA-Seed");
    let digest = sha256_digest(b"ToyCredential-183B-MSO-Payload");
    let sig = kp.sign_prehashed(&digest);

    let circuit = build_p256_ecdsa_curve_circuit();
    let witness = build_p256_ecdsa_curve_witness(&kp.public_key, &digest, &sig)
        .expect("Świadek ECDSA musi zostać wygenerowany");

    let public_inputs = [
        (0usize, Fp256::one()),
        (1usize, kp.public_key.x),
        (2usize, kp.public_key.y),
    ];

    // 2 warstwy (12 i 10 przewodów => 8 + 8 = 16 rund => 48 padów) + 10 wejść = 58 elementów
    let params = Protocol25Params::new(6, 12, 20, 48, 8);

    let mut p_tr = FiatShamirTranscript::new(b"ZeroAge-Paper-Alg4-ECDSA");
    let proof = Protocol25Prover::prove_layered(
        &circuit,
        &witness,
        &public_inputs,
        &params,
        &mut p_tr,
        &mut rng,
    )
    .expect("Generowanie dowodu ZKP dla Algorytmu 4 (ECDSA P-256) musi się powieść");

    let mut v_tr = FiatShamirTranscript::new(b"ZeroAge-Paper-Alg4-ECDSA");
    Protocol25Verifier::verify_layered(&circuit, &public_inputs, &params, &proof, &mut v_tr)
        .expect("Weryfikacja ZKP dla Algorytmu 4 (ECDSA P-256) musi się powieść");
}

#[test]
fn test_paper_compliance_sha256_round_circuit_in_protocol25() {
    let mut rng = test_rng();
    let sha_sub = build_sha256_round_nonlinear_circuit::<Fp256>();

    let (a, b, c) = (SHA256_H0[0], SHA256_H0[1], SHA256_H0[2]);
    let (e, f, g) = (SHA256_H0[4], SHA256_H0[5], SHA256_H0[6]);
    let expected_ch_bits = u32_to_field_bits_be::<Fp256>(ch(e, f, g));
    let expected_maj_bits = u32_to_field_bits_be::<Fp256>(maj(a, b, c));

    // Nakładamy warstwę wyjściową 0 sprawdzającą równość Ch, Maj oraz zerowość bit-checków
    let mut assert_gates = Vec::with_capacity(96);
    for i in 0..32 {
        assert_gates.push(QuadGate::new(
            1 + i,
            vec![
                QuadTerm::linear(1 + i, Fp256::one()),
                QuadTerm::constant(-expected_ch_bits[i]),
            ],
        ));
        assert_gates.push(QuadGate::new(
            33 + i,
            vec![
                QuadTerm::linear(33 + i, Fp256::one()),
                QuadTerm::constant(-expected_maj_bits[i]),
            ],
        ));
        assert_gates.push(QuadGate::scale(65 + i, 65 + i, Fp256::one()));
    }
    let layer0 = CircuitLayer::new(0, 97, 97, assert_gates);
    let full_circuit = LayeredCircuit::new(
        vec![layer0, sha_sub.layers[0].clone(), sha_sub.layers[1].clone()],
        193,
    );

    let witness = build_sha256_round_witness::<Fp256>(e, f, g, a, b, c);
    let public_inputs = [(0usize, Fp256::one())];

    // 3 warstwy (97, 257, 193 => 14 + 18 + 16 = 48 rund => 144 padów) + 193 wejść = 337 elementów
    let params = Protocol25Params::new(16, 24, 32, 64, 8);

    let mut p_tr = FiatShamirTranscript::new(b"ZeroAge-Paper-Sec42-SHA256");
    let proof = Protocol25Prover::prove_layered(
        &full_circuit,
        &witness,
        &public_inputs,
        &params,
        &mut p_tr,
        &mut rng,
    )
    .expect("Generowanie dowodu ZKP dla rundy SHA-256 musi się powieść");

    let mut v_tr = FiatShamirTranscript::new(b"ZeroAge-Paper-Sec42-SHA256");
    Protocol25Verifier::verify_layered(&full_circuit, &public_inputs, &params, &proof, &mut v_tr)
        .expect("Weryfikacja ZKP dla rundy SHA-256 musi się powieść");
}

// ===========================================================================
// 5 PLANOWANYCH TESTÓW BEZPIECZEŃSTWA (Rozdział 5 Specyfikacji Projektu)
// ===========================================================================

#[test]
fn test_security_1_underage_and_modular_underflow_resistance() {
    let mut rng = test_rng();
    let mut issuer = CredentialIssuer::new("Urząd-SecTest", b"sec-test-seed");
    let valid_from = CredentialDate::parse_iso("2026-01-01").unwrap();
    let valid_until = CredentialDate::parse_iso("2027-01-01").unwrap();
    let verify_date = CredentialDate::parse_iso("2026-11-17").unwrap();

    // 1A. Osoba z grudnia 2008 (ma 17 lat w listopadzie 2026 -> is_over18 = false)
    let dec_minor_dob = CredentialDate::parse_iso("2008-12-15").unwrap();
    let minor_cred = issuer
        .issue_age_credential("Małolat Grudniowy", dec_minor_dob, valid_from, valid_until)
        .unwrap();
    assert!(!minor_cred.private_witness.is_over18);
    assert!(
        generate_mvp_age_proof(&minor_cred, verify_date, [0x11u8; 16], &mut rng).is_err(),
        "Test 1: Osoba niepełnoletnia (is_over18 = false) nie może wygenerować dowodu"
    );

    // 1B. Próba użycia ujemnej różnicy czasu (przepełnienie modulo p: t_now < valid_from => p - 1)
    let circuit = build_age_and_validity_circuit::<Fp256>();
    let t_now = verify_date.to_timestamp_seconds();
    let future_valid_from = t_now + 86_400; // certyfikat ważny dopiero od jutra (t_now - valid_from = -86400 = p - 86400)
    let bad_witness = build_age_and_validity_witness(
        t_now,
        true,
        future_valid_from,
        valid_until.to_timestamp_seconds(),
        Fp256::from(123u64),
        Fp256::from(123u64),
    );
    let evals = circuit.evaluate_all(&bad_witness);
    assert!(
        !is_age_circuit_output_satisfied(&evals[0]),
        "Test 1: Niedomiar modularny (t_now - valid_from < 0 => p - delta) musi zostać odrzucony przez 64-bitowe bramki zakresu"
    );

    // 1C. Próba podszycia się przez ustawienie w[3] = 2 (nie-bit) w obwodzie
    let mut non_bit_witness = build_age_and_validity_witness(
        t_now,
        true,
        valid_from.to_timestamp_seconds(),
        valid_until.to_timestamp_seconds(),
        Fp256::from(123u64),
        Fp256::from(123u64),
    );
    non_bit_witness[3] = Fp256::from(2u64);
    assert!(!is_age_circuit_output_satisfied(&circuit.evaluate_all(&non_bit_witness)[0]));
}

#[test]
fn test_security_2_replay_attack_resistance() {
    let mut rng = test_rng();
    let mut issuer = CredentialIssuer::new("Urząd-SecTest", b"sec-test-seed");
    let valid_from = CredentialDate::parse_iso("2026-01-01").unwrap();
    let valid_until = CredentialDate::parse_iso("2027-01-01").unwrap();
    let verify_date = CredentialDate::parse_iso("2026-11-17").unwrap();
    let adult_dob = CredentialDate::parse_iso("2000-03-10").unwrap();

    let cred = issuer
        .issue_age_credential("Jan Kowalski", adult_dob, valid_from, valid_until)
        .unwrap();

    let session_nonce = [0x55u8; 16];
    let proof = generate_mvp_age_proof(&cred, verify_date, session_nonce, &mut rng).unwrap();
    let intercepted_json = proof.to_json_pretty().unwrap();

    // Pierwsza sesja: uczciwy użytkownik loguje się z przechwyconym JSON-em
    let mut replay_cache = NonceReplayCache::new();
    let decoded_1 = MvpAgeProof::from_json_str(&intercepted_json).unwrap();
    assert!(verify_mvp_age_proof_full(
        &decoded_1,
        &issuer.public_key(),
        &issuer.revocation_registry,
        &mut replay_cache
    )
    .is_ok());

    // Atakujący podsłuchał plik JSON i wysyła go powtórnie w nowej transakcji:
    let decoded_2 = MvpAgeProof::from_json_str(&intercepted_json).unwrap();
    assert!(
        verify_mvp_age_proof_full(
            &decoded_2,
            &issuer.public_key(),
            &issuer.revocation_registry,
            &mut replay_cache
        )
        .is_err(),
        "Test 2: Ponowne przesłanie tego samego proof.json musi zostać odrzucone (Replay Attack)"
    );

    // Atakujący próbuje podmienić challenge_nonce w przechwyconym JSON-ie na nowy:
    let mut modified_nonce_proof = decoded_1;
    modified_nonce_proof.public_inputs.challenge_nonce = [0x99u8; 16];
    assert!(
        verify_mvp_age_proof(&modified_nonce_proof, &issuer.public_key()).is_err(),
        "Test 2: Podmiana challenge_nonce w gotowym proof.json łamie transkrypt Fiata-Shamira"
    );
}

#[test]
fn test_security_3_issuer_signature_and_credential_integrity() {
    let mut rng = test_rng();
    let mut real_issuer = CredentialIssuer::new("Urząd-Państwowy", b"real-issuer-seed");
    let mut rogue_issuer = CredentialIssuer::new("Urząd-Państwowy", b"rogue-attacker-seed");

    let valid_from = CredentialDate::parse_iso("2026-01-01").unwrap();
    let valid_until = CredentialDate::parse_iso("2027-01-01").unwrap();
    let verify_date = CredentialDate::parse_iso("2026-11-17").unwrap();
    let minor_dob = CredentialDate::parse_iso("2012-06-01").unwrap();

    // 3A. Małolat modyfikuje swoje lokalne poświadczenie w JSON (zmienia is_over18 z false na true)
    let mut forged_cred = real_issuer
        .issue_age_credential("Oszust", minor_dob, valid_from, valid_until)
        .unwrap();
    forged_cred.private_witness.is_over18 = true;
    assert!(
        generate_mvp_age_proof(&forged_cred, verify_date, [0x22u8; 16], &mut rng).is_err(),
        "Test 3: Lokalne ustawienie is_over18 = true bez zgody Wystawcy nie otwiera zobowiązania"
    );

    // 3B. Atakujący podpisuje własne fałszywe poświadczenie swoim nieautoryzowanym kluczem prywatnym
    let rogue_cred = rogue_issuer
        .issue_over18_flag_credential("Oszust", true, valid_from, valid_until)
        .unwrap();
    let rogue_proof =
        generate_mvp_age_proof(&rogue_cred, verify_date, [0x33u8; 16], &mut rng).unwrap();
    assert!(
        verify_mvp_age_proof(&rogue_proof, &real_issuer.public_key()).is_err(),
        "Test 3: Dowód z poświadczenia podpisanego obcym kluczem musi zostać odrzucony przez Weryfikatora"
    );
}

#[test]
fn test_security_4_revocation_and_expiration_handling() {
    let mut rng = test_rng();
    let mut issuer = CredentialIssuer::new("Urząd-SecTest", b"sec-test-seed");
    let valid_from = CredentialDate::parse_iso("2026-01-01").unwrap();
    let valid_until = CredentialDate::parse_iso("2026-11-10").unwrap();
    let adult_dob = CredentialDate::parse_iso("1999-01-01").unwrap();

    let cred = issuer
        .issue_age_credential("Anna Nowak", adult_dob, valid_from, valid_until)
        .unwrap();

    // 4A. Weryfikacja po wygaśnięciu certyfikatu (2026-11-17 > 2026-11-10)
    let expired_verify_date = CredentialDate::parse_iso("2026-11-17").unwrap();
    assert!(
        generate_mvp_age_proof(&cred, expired_verify_date, [0x44u8; 16], &mut rng).is_err(),
        "Test 4: Wygasły certyfikat musi zostać odrzucony przez obwód ważności"
    );

    // 4B. Weryfikacja w terminie ważności, ale certyfikat został unieważniony w rejestrze Wystawcy
    let valid_verify_date = CredentialDate::parse_iso("2026-11-05").unwrap();
    let proof = generate_mvp_age_proof(&cred, valid_verify_date, [0x45u8; 16], &mut rng).unwrap();
    issuer.revoke_credential(cred.credential_id, valid_verify_date, "Kradzież telefonu");

    let mut replay_cache = NonceReplayCache::new();
    assert!(
        verify_mvp_age_proof_full(
            &proof,
            &issuer.public_key(),
            &issuer.revocation_registry,
            &mut replay_cache
        )
        .is_err(),
        "Test 4: Unieważniony certyfikat musi zostać odrzucony przez Weryfikatora"
    );
}

#[test]
fn test_security_5_zero_knowledge_privacy_and_unlinkability_audit() {
    let mut rng = test_rng();
    let mut issuer = CredentialIssuer::new("Urząd-SecTest", b"sec-test-seed");
    let valid_from = CredentialDate::parse_iso("2026-01-01").unwrap();
    let valid_until = CredentialDate::parse_iso("2027-01-01").unwrap();
    let verify_date = CredentialDate::parse_iso("2026-11-17").unwrap();
    let adult_dob = CredentialDate::parse_iso("2001-09-20").unwrap();

    let cred = issuer
        .issue_age_credential("Tajny Obywatel", adult_dob, valid_from, valid_until)
        .unwrap();

    let proof_1 = generate_mvp_age_proof(&cred, verify_date, [0x71u8; 16], &mut rng).unwrap();
    let proof_2 = generate_mvp_age_proof(&cred, verify_date, [0x72u8; 16], &mut rng).unwrap();

    let json_1 = proof_1.to_json_pretty().unwrap();
    let json_2 = proof_2.to_json_pretty().unwrap();

    // 5A. Audyt serializacji JSON: sól, etykieta posiadacza i 64-bitowy timestamp daty urodzenia nie występują w proof.json
    let salt_hex: String = cred
        .private_witness
        .secret_salt
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let dob_ts_hex = format!("{:016x}", adult_dob.to_timestamp_seconds());
    assert!(
        !json_1.contains(&salt_hex),
        "Test 5: Tajna sól nie może wyciec w proof.json"
    );
    assert!(
        !json_1.contains(&dob_ts_hex),
        "Test 5: Znacznik czasu daty urodzenia nie może wyciec w proof.json"
    );
    assert!(!json_1.contains("Tajny Obywatel"));
    assert!(!json_1.contains("2001-09-20"));

    // 5B. Audyt losowości ZKP: dwa dowody dla tego samego certyfikatu mają różne commitmenty Ligero i transkrypty
    assert_ne!(proof_1.ligero_root, proof_2.ligero_root);
    assert_ne!(proof_1.masked_transcript, proof_2.masked_transcript);
    assert_ne!(json_1, json_2);

    // 5C. Audyt kolumn Ligero: otwierane są wyłącznie kolumny z części parzystości [k, n)
    let params = mdoc_app::mvp_flow::mvp_protocol25_params();
    for (col_idx, _, _) in &proof_1.ligero_openings {
        assert!(*col_idx >= params.k && *col_idx < params.n);
    }
}

// ===========================================================================
// RAPORT POMIARÓW WYDAJNOŚCIOWYCH E2E (Etap 4 Specyfikacji)
// ===========================================================================

#[test]
fn test_e2e_performance_benchmarks_report() {
    let mut rng = test_rng();
    let valid_from = CredentialDate::parse_iso("2026-01-01").unwrap();
    let valid_until = CredentialDate::parse_iso("2027-01-01").unwrap();
    let verify_date = CredentialDate::parse_iso("2026-11-17").unwrap();
    let dob = CredentialDate::parse_iso("2000-05-15").unwrap();

    let t_issue = Instant::now();
    let mut issuer = CredentialIssuer::new("Urząd-Bench", b"bench-issuer-seed");
    let cred = issuer
        .issue_age_credential("Obywatel Bench", dob, valid_from, valid_until)
        .unwrap();
    let issue_ms = t_issue.elapsed().as_secs_f64() * 1000.0;

    let t_prove = Instant::now();
    let proof = generate_mvp_age_proof(&cred, verify_date, [0xABu8; 16], &mut rng).unwrap();
    let prove_ms = t_prove.elapsed().as_secs_f64() * 1000.0;

    let proof_json = proof.to_json_pretty().unwrap();
    let decoded = MvpAgeProof::from_json_str(&proof_json).unwrap();

    let mut replay_cache = NonceReplayCache::new();
    let t_verify = Instant::now();
    verify_mvp_age_proof_full(
        &decoded,
        &issuer.public_key(),
        &issuer.revocation_registry,
        &mut replay_cache,
    )
    .unwrap();
    let verify_ms = t_verify.elapsed().as_secs_f64() * 1000.0;

    println!("\n=== Raport Wydajności E2E (Model is_over18 + Protokół 2.5 nad F_p256) ===");
    println!("  1. Emisja certyfikatu (ECDSA P-256 + SHA-256): {:7.2} ms", issue_ms);
    println!("  2. Generowanie dowodu ZKP (Prover):            {:7.2} ms", prove_ms);
    println!("  3. Weryfikacja dowodu ZKP + ECDSA (Verifier):  {:7.2} ms", verify_ms);
    println!("  4. Rozmiar paczki proof.json:                  {:7.2} KB ({} B)", proof_json.len() as f64 / 1024.0, proof_json.len());
}
