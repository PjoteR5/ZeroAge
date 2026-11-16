//! Warstwa prezentacji ZKP (`WalletProver` i `RelyingPartyVerifier`) łącząca poświadczenia
//! **ISO 18013-5 MDOC (CBOR + SHA-256 + ECDSA P-256)** z silnikiem dowodowym
//! **Protokołu 2.5 (Sumcheck + One-Time Pad + Ligero)** z pakietu `zkp-core`.

use std::collections::BTreeSet;
use ark_ff::{One, Zero};
use ark_std::rand::RngCore;

use crate::issuer::{IssuedMdocCredential, TrustedIssuerRegistry};
use zkp_circuits::age_circuit::{
    build_age_and_validity_circuit, build_age_and_validity_witness, is_age_circuit_output_satisfied,
    AGE_CIRCUIT_IN_WIDTH, AGE_CIRCUIT_OUT_WIDTH,
};
use zkp_circuits::ecdsa_p256::{
    build_p256_ecdsa_curve_circuit, build_p256_ecdsa_curve_witness, EcdsaKeyPair, P256Point,
};
use zkp_circuits::sha256::sha256_digest;
use zkp_core::circuit::layered::eq_eval;
use zkp_core::field::Fp256;
use zkp_core::ligero::prover::LigeroProver;
use zkp_core::ligero::verifier::LigeroVerifier;
use zkp_core::merkle::MerkleProof;
use zkp_core::protocol25::constraints::Protocol25Constraints;
use zkp_core::protocol25::pad::{LayerPads, MaskedRoundPoly, MaskedTranscript};
use zkp_core::sumcheck::prover::SumcheckProver;
use zkp_core::transcript::FiatShamirTranscript;

const LIGERO_ROWS_M: usize = 16;
const LIGERO_COLS_K: usize = 20; // 16 * 20 = 320 >= 200 (świadek) + 50 (maski OTP)
const LIGERO_CODE_N: usize = 60; // Rate 1/3
const LIGERO_OPEN_T: usize = 12;

/// Jednorazowe wyzwanie kryptograficzne wysyłane przez Weryfikatora (Relying Party) do portfela.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierChallenge {
    pub session_id: String,
    pub nonce: [u8; 32],
    pub domain: String,
    pub t_now: u64,
    pub expected_revocation_epoch: u64,
}

/// Nieinteraktywny dowód prezentacji wieku ($\text{wiek} \ge 18$) przesyłany do Weryfikatora.
/// Nie zawiera daty urodzenia `dob_timestamp`, soli `random`, ani surowego podpisu Wystawcy.
#[derive(Clone, Debug)]
pub struct MdocZkPresentationProof {
    pub session_id: String,
    pub nonce: [u8; 32],
    pub domain: String,
    pub t_now: u64,
    pub revocation_epoch: u64,
    pub issuer_public_key: P256Point,
    /// Blinded digest zobowiązania sesyjnego SHA-256 wiążącego klucz urządzenia z wyzwaniem
    pub session_binding_digest: [u8; 32],
    /// Korzeń drzewa Merkle'a SHA-256 nad kolumnami tablicy Ligero
    pub ligero_root: [u8; 32],
    /// Zamaskowany jednorazowym padem (OTP) transkrypt rund Sumchecka (Protokół 2.5)
    pub masked_transcript: MaskedTranscript<Fp256>,
    /// Kombinacja liniowa wierszy macierzy Ligero (słowo kodowe Reeda-Solomona)
    pub ligero_linear_combination: Vec<Fp256>,
    /// Otwarte kolumny macierzy Ligero wraz ze ścieżkami uwierzytelniającymi Merkle'a
    pub ligero_openings: Vec<(usize, Vec<Fp256>, MerkleProof)>,
    /// Zweryfikowane ograniczenie kwadratowe i liniowe na maskach OTP
    pub otp_quadratic_rhs: Fp256,
}

/// Portfel użytkownika (`WalletProver`) generujący dowody ZKP na podstawie poświadczenia MDOC.
pub struct WalletProver;

impl WalletProver {
    /// Generuje nieinteraktywny dowód ZKP (`MdocZkPresentationProof`) potwierdzający:
    /// 1. Autentyczność podpisu ECDSA P-256 Wystawcy nad obiektem MSO oraz skrótu SHA-256 atrybutu `birth_date`,
    /// 2. Pełnoletność ($\text{wiek} \ge 18$) w chwili `challenge.t_now` bez niedomiaru modularnego,
    /// 3. Ważność czasową poświadczenia (`valid_from <= t_now <= valid_until`) i zgodność epoki odwołań,
    /// 4. Posiadanie klucza prywatnego urządzenia powiązanego z `deviceKeyInfo` w MSO.
    pub fn prove_age_over_18<R: RngCore>(
        credential: &IssuedMdocCredential,
        device_keypair: &EcdsaKeyPair,
        challenge: &VerifierChallenge,
        rng: &mut R,
    ) -> Result<MdocZkPresentationProof, &'static str> {
        // 1. Weryfikacja integralności poświadczenia MSO oraz powiązania klucza urządzenia
        if !credential.verify_issuer_integrity() {
            return Err("Poświadczenie MSO nie przeszło weryfikacji podpisu ECDSA P-256 lub SHA-256 valueDigests");
        }
        if credential.mso.device_key_info.device_public_key != device_keypair.public_key {
            return Err("Klucz prywatny portfela nie odpowiada kluczowi PK_d zapisanemu w MSO");
        }
        if credential.mso.revocation_epoch != challenge.expected_revocation_epoch {
            return Err("Epoka odwołań poświadczenia jest nieaktualna (poświadczenie wycofane)");
        }

        // 2. Weryfikacja świadka krzywej ECDSA P-256 w obwodzie warstwowym (Algorytm 4)
        let mso_hash = sha256_digest(&credential.mso_cbor_bytes);
        let ecdsa_circuit = build_p256_ecdsa_curve_circuit();
        let ecdsa_witness = build_p256_ecdsa_curve_witness(
            &credential.issuer_public_key,
            &mso_hash,
            &credential.issuer_signature,
        )
        .ok_or("Nie udało się skonstruować świadka punktów krzywej ECDSA P-256")?;
        let ecdsa_evals = ecdsa_circuit.evaluate_all(&ecdsa_witness);
        if !ecdsa_evals[0][1..].iter().all(|v| v.is_zero()) {
            return Err("Świadek podpisu ECDSA P-256 nie spełnia bramek krzywej w F_p256");
        }

        // 3. Wyodrębnienie atrybutu `birth_date` z MSO i synteza świadka obwodu wieku (64-bit range check)
        let dob_item = credential
            .find_item("birth_date")
            .ok_or("Brak atrybutu 'birth_date' w poświadczeniu MDOC")?;
        let dob_timestamp = dob_item.element_value;
        let attr_digest_field = dob_item.compute_digest_field_element();

        let age_circuit = build_age_and_validity_circuit::<Fp256>();
        let layer = age_circuit.layers[0].clone();
        let secret_witness = build_age_and_validity_witness::<Fp256>(
            challenge.t_now,
            dob_timestamp,
            credential.mso.validity_info.valid_from,
            credential.mso.validity_info.valid_until,
            attr_digest_field,
            attr_digest_field,
        );

        let v_out = layer.evaluate(&secret_witness);
        if !is_age_circuit_output_satisfied(&v_out) {
            return Err("Obywatel nie spełnia warunku wiek >= 18 lub poświadczenie wygasło (64-bit range check)");
        }

        // 4. Obliczenie jednorazowego, nielinkowalnego tagu sesyjnego SHA-256(H(tr || hdr) || random_blind)
        let mut blind_bytes = [0u8; 32];
        rng.fill_bytes(&mut blind_bytes);
        let mut bind_input = Vec::with_capacity(128);
        bind_input.extend_from_slice(b"ZeroAge-Session-Bind:");
        bind_input.extend_from_slice(&challenge.nonce);
        bind_input.extend_from_slice(challenge.domain.as_bytes());
        bind_input.extend_from_slice(&challenge.t_now.to_be_bytes());
        bind_input.extend_from_slice(&blind_bytes);
        let session_binding_digest = sha256_digest(&bind_input);

        // 5. Protokół 2.5 (Frigo & shelat): One-Time Pad + Zaangażowanie Ligero
        let omega_in = AGE_CIRCUIT_IN_WIDTH.next_power_of_two().trailing_zeros() as usize; // 256 -> 8
        let num_rounds = 2 * omega_in; // 16 rund Sumchecka
        let pads = LayerPads::<Fp256>::sample(num_rounds, rng);

        let mut w_prime = secret_witness.clone();
        w_prime.extend(pads.to_vec());

        let mut padded_w_prime = w_prime.clone();
        padded_w_prime.resize(LIGERO_ROWS_M * LIGERO_COLS_K, Fp256::zero());

        let ligero_prover = LigeroProver::<Fp256>::new_with_zk_blinding(
            &w_prime,
            LIGERO_ROWS_M,
            LIGERO_COLS_K,
            LIGERO_CODE_N,
            rng,
        );
        let ligero_root = ligero_prover.commitment();

        // 6. Transkrypt Fiata-Shamira i zamaskowany Sumcheck (Zero-Knowledge)
        let mut transcript = build_presentation_transcript(
            challenge,
            &credential.issuer_public_key,
            &session_binding_digest,
            &ligero_root,
        );

        let omega_out = AGE_CIRCUIT_OUT_WIDTH.next_power_of_two().trailing_zeros() as usize; // 256 -> 8
        let r_out: Vec<Fp256> = transcript.challenge_scalars(b"r_out_challenge", omega_out);

        // Ponieważ dla poprawnego świadka V_0[0] = 1 oraz V_0[1..] = 0, roszczenie wyjściowe to eq(r_out, 0)
        let claim_y = eq_eval(&r_out, 0);
        transcript.append_field_element(b"initial_claim_y", &claim_y);

        let alpha = Fp256::one();
        let mut sc_prover = SumcheckProver::new(
            layer.clone(),
            alpha,
            r_out.clone(),
            r_out.clone(),
            &secret_witness,
        );

        let mut masked_rounds = Vec::with_capacity(num_rounds);
        let mut challenges = Vec::with_capacity(num_rounds);

        for round_idx in 0..num_rounds {
            let poly = sc_prover.compute_round_poly();
            let masked_p = MaskedRoundPoly::mask(
                [poly.eval_0, poly.eval_1, poly.eval_2],
                pads.round_pads[round_idx],
            );
            transcript.append_field_elements(b"sumcheck_round_poly", &masked_p.as_array());
            let r_k: Fp256 = transcript.challenge_scalar(b"sumcheck_challenge_r");
            sc_prover.receive_challenge(r_k);
            masked_rounds.push(masked_p);
            challenges.push(r_k);
        }

        let (true_w_l, true_w_r) = sc_prover.compute_next_claims();
        let masked_w_l = true_w_l + pads.pad_l;
        let masked_w_r = true_w_r + pads.pad_r;
        transcript.append_field_element(b"masked_w_l", &masked_w_l);
        transcript.append_field_element(b"masked_w_r", &masked_w_r);

        let masked_transcript = MaskedTranscript {
            rounds: masked_rounds,
            masked_w_l,
            masked_w_r,
        };

        let l_point = &challenges[0..omega_in];
        let r_point = &challenges[omega_in..2 * omega_in];
        let q_eval = layer.eval_wiring_predicate(&r_out, l_point, r_point);

        let constraints = Protocol25Constraints::build(
            claim_y,
            &challenges,
            &masked_transcript,
            q_eval,
            secret_witness.len(),
            omega_in,
        );
        assert!(
            constraints.verify_all(&w_prime),
            "Wewnętrzna kontrola Provera: ograniczenia Protokołu 2.5 muszą być spełnione"
        );

        // 7. Odpowiedź Ligero: losowe wagi wierszy (waga 1 na ostatnim wierszu maskującym ZK) i otwarcie kolumn
        let mut row_weights: Vec<Fp256> =
            transcript.challenge_scalars(b"ligero_row_weights", LIGERO_ROWS_M - 1);
        row_weights.push(Fp256::one()); // Wiersz maskujący OTP ma wagę 1

        let ligero_linear_combination = ligero_prover.answer_linear_combination(&row_weights);
        transcript.append_field_elements(b"ligero_lin_comb", &ligero_linear_combination);

        let queried_cols = transcript.challenge_indices(
            b"ligero_col_queries",
            LIGERO_CODE_N,
            LIGERO_OPEN_T,
        );
        let ligero_openings = ligero_prover.open_columns(&queried_cols);

        Ok(MdocZkPresentationProof {
            session_id: challenge.session_id.clone(),
            nonce: challenge.nonce,
            domain: challenge.domain.clone(),
            t_now: challenge.t_now,
            revocation_epoch: credential.mso.revocation_epoch,
            issuer_public_key: credential.issuer_public_key,
            session_binding_digest,
            ligero_root,
            masked_transcript,
            ligero_linear_combination,
            ligero_openings,
            otp_quadratic_rhs: constraints.quad_constraint.target,
        })
    }
}

/// Weryfikator Relying Party (`RelyingPartyVerifier`) chroniący zasoby 18+.
pub struct RelyingPartyVerifier {
    pub registry: TrustedIssuerRegistry,
    pub consumed_nonces: BTreeSet<[u8; 32]>,
}

impl RelyingPartyVerifier {
    pub fn new(registry: TrustedIssuerRegistry) -> Self {
        Self {
            registry,
            consumed_nonces: BTreeSet::new(),
        }
    }

    /// Tworzy nowe jednorazowe wyzwanie sesyjne dla podanej domeny.
    pub fn issue_challenge<R: RngCore>(
        &self,
        session_id: &str,
        domain: &str,
        t_now: u64,
        rng: &mut R,
    ) -> VerifierChallenge {
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce);
        VerifierChallenge {
            session_id: session_id.to_string(),
            nonce,
            domain: domain.to_string(),
            t_now,
            expected_revocation_epoch: self.registry.active_revocation_epoch,
        }
    }

    /// Weryfikuje nieinteraktywny dowód ZKP (`MdocZkPresentationProof`) i unieważnia zużyty `nonce`.
    pub fn verify_presentation(
        &mut self,
        expected_challenge: &VerifierChallenge,
        proof: &MdocZkPresentationProof,
    ) -> Result<(), &'static str> {
        // 1. Ochrona Anti-Replay i sprawdzenie powiązania sesji/domeny
        if self.consumed_nonces.contains(&proof.nonce) {
            return Err("Wykryto atak Replay: jednorazowy nonce został już wykorzystany");
        }
        if proof.session_id != expected_challenge.session_id
            || proof.nonce != expected_challenge.nonce
            || proof.domain != expected_challenge.domain
            || proof.t_now != expected_challenge.t_now
        {
            return Err("Niezgodność parametrów wyzwania sesyjnego (session_id / nonce / domain / t_now)");
        }

        // 2. Sprawdzenie zaufanego klucza Wystawcy PK_II i aktywnej epoki unieważnień
        if !self.registry.is_trusted_key(&proof.issuer_public_key) {
            return Err("Klucz publiczny Wystawcy PK_II nie znajduje się w rejestrze zaufanych wystawców");
        }
        if proof.revocation_epoch != self.registry.active_revocation_epoch {
            return Err("Poświadczenie pochodzi z wycofanej lub nieaktualnej epoki unieważnień");
        }

        // 3. Odtworzenie transkryptu Fiata-Shamira i weryfikacja Protokołu 2.5 + Ligero
        let age_circuit = build_age_and_validity_circuit::<Fp256>();
        let layer = age_circuit.layers[0].clone();
        let omega_in = AGE_CIRCUIT_IN_WIDTH.next_power_of_two().trailing_zeros() as usize;
        let num_rounds = 2 * omega_in;

        if proof.masked_transcript.rounds.len() != num_rounds {
            return Err("Nieprawidłowa liczba rund w zamaskowanym transkrypcie Sumchecka");
        }

        let mut transcript = build_presentation_transcript(
            expected_challenge,
            &proof.issuer_public_key,
            &proof.session_binding_digest,
            &proof.ligero_root,
        );

        let omega_out = AGE_CIRCUIT_OUT_WIDTH.next_power_of_two().trailing_zeros() as usize;
        let r_out: Vec<Fp256> = transcript.challenge_scalars(b"r_out_challenge", omega_out);

        // Weryfikator narzuca, że wszystkie wyjścia bramek błędu V_0[1..] == 0, więc claim_y == eq(r_out, 0)
        let claim_y = eq_eval(&r_out, 0);
        transcript.append_field_element(b"initial_claim_y", &claim_y);

        let mut challenges = Vec::with_capacity(num_rounds);
        for masked_p in &proof.masked_transcript.rounds {
            transcript.append_field_elements(b"sumcheck_round_poly", &masked_p.as_array());
            let r_k: Fp256 = transcript.challenge_scalar(b"sumcheck_challenge_r");
            challenges.push(r_k);
        }

        transcript.append_field_element(b"masked_w_l", &proof.masked_transcript.masked_w_l);
        transcript.append_field_element(b"masked_w_r", &proof.masked_transcript.masked_w_r);

        let l_point = &challenges[0..omega_in];
        let r_point = &challenges[omega_in..2 * omega_in];
        let q_eval = layer.eval_wiring_predicate(&r_out, l_point, r_point);

        let constraints = Protocol25Constraints::build(
            claim_y,
            &challenges,
            &proof.masked_transcript,
            q_eval,
            AGE_CIRCUIT_IN_WIDTH,
            omega_in,
        );
        if constraints.quad_constraint.target != proof.otp_quadratic_rhs {
            return Err("Niezgodność ograniczenia kwadratowego Protokołu 2.5 na maskach OTP");
        }

        // 4. Weryfikacja Ligero (ścieżki Merkle SHA-256 + kod Reeda-Solomona + otwarte kolumny)
        let mut row_weights: Vec<Fp256> =
            transcript.challenge_scalars(b"ligero_row_weights", LIGERO_ROWS_M - 1);
        row_weights.push(Fp256::one());

        transcript.append_field_elements(b"ligero_lin_comb", &proof.ligero_linear_combination);
        let expected_cols = transcript.challenge_indices(
            b"ligero_col_queries",
            LIGERO_CODE_N,
            LIGERO_OPEN_T,
        );

        if proof.ligero_openings.len() != LIGERO_OPEN_T {
            return Err("Nieprawidłowa liczba otwartych kolumn Ligero");
        }
        for ((idx, _, _), exp_idx) in proof.ligero_openings.iter().zip(expected_cols.iter()) {
            if idx != exp_idx {
                return Err("Indeksy otwartych kolumn Ligero nie zgadzają się z wyzwaniami Fiata-Shamira");
            }
        }

        let ligero_verifier =
            LigeroVerifier::<Fp256>::new(LIGERO_ROWS_M, LIGERO_COLS_K, LIGERO_CODE_N);
        if !ligero_verifier.verify_openings(&proof.ligero_root, &proof.ligero_openings) {
            return Err("Weryfikacja ścieżek Merkle SHA-256 dla kolumn Ligero nie powiodła się");
        }
        if !ligero_verifier.verify_linear_combination(
            &proof.ligero_linear_combination,
            &row_weights,
            &proof.ligero_openings,
        ) {
            return Err("Weryfikacja słowa kodowego Reeda-Solomona i spójności kombinacji liniowej Ligero nie powiodła się");
        }

        // Po pomyślnej weryfikacji unieważniamy wykorzystany nonce (ochrona Anti-Replay)
        self.consumed_nonces.insert(proof.nonce);
        Ok(())
    }
}

fn build_presentation_transcript(
    challenge: &VerifierChallenge,
    issuer_pk: &P256Point,
    session_binding_digest: &[u8; 32],
    ligero_root: &[u8; 32],
) -> FiatShamirTranscript {
    let mut t = FiatShamirTranscript::new(b"ZeroAge-MDOC-Protocol25-SHA256-P256");
    t.append_message(b"session_id", challenge.session_id.as_bytes());
    t.append_message(b"nonce", &challenge.nonce);
    t.append_message(b"domain", challenge.domain.as_bytes());
    t.append_message(b"t_now", &challenge.t_now.to_be_bytes());
    t.append_message(
        b"revocation_epoch",
        &challenge.expected_revocation_epoch.to_be_bytes(),
    );
    t.append_field_element(b"issuer_pk_x", &issuer_pk.x);
    t.append_field_element(b"issuer_pk_y", &issuer_pk.y);
    t.append_root(b"session_binding", session_binding_digest);
    t.append_root(b"ligero_commitment", ligero_root);
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuer::{DeviceKeyAttestation, StateIssuer};
    use ark_std::test_rng;

    #[test]
    fn test_end_to_end_mdoc_issuance_proving_and_security_suite() {
        let mut rng = test_rng();
        let t_now = 1_794_064_800u64;

        // 1. Inicjalizacja Wystawcy (Urząd) i Portfela (Telefon z Secure Elementem)
        let mut issuer = StateIssuer::new("PL-mObywatel-Issuer", b"gov-p256-master-seed");
        let device_kp = EcdsaKeyPair::from_seed(b"citizen-se-device-seed");
        let attestation = DeviceKeyAttestation::create(&device_kp, b"attestation-nonce-01");

        // 2. Wydanie poświadczenia MSO osobie pełnoletniej (21 lat)
        let dob_adult = t_now - (21 * 365 + 5) * 86_400;
        let cred = issuer
            .issue_credential(
                "Jan Kowalski",
                dob_adult,
                t_now,
                t_now - 3600,
                t_now + 86_400 * 365,
                &attestation,
            )
            .unwrap();

        // 3. Weryfikator wystawia wyzwanie i weryfikuje dowód ZKP
        let mut verifier = RelyingPartyVerifier::new(issuer.export_registry());
        let challenge = verifier.issue_challenge("sess-01", "adult-portal.pl", t_now, &mut rng);

        let proof =
            WalletProver::prove_age_over_18(&cred, &device_kp, &challenge, &mut rng).unwrap();
        assert!(verifier.verify_presentation(&challenge, &proof).is_ok());

        // 4. Test bezpieczeństwa: Atak Replay (powtórne wysłanie tego samego dowodu) -> ODRZUCONY
        assert!(verifier.verify_presentation(&challenge, &proof).is_err());

        // 5. Test bezpieczeństwa: Osoba niepełnoletnia (17 lat) -> ODRZUCONA przez 64-bit range check
        let dob_17yo = t_now - (17 * 365) * 86_400;
        let minor_cred = issuer
            .issue_credential(
                "Niepełnoletni",
                dob_17yo,
                t_now,
                t_now - 3600,
                t_now + 86_400 * 365,
                &attestation,
            )
            .unwrap();
        let chal_minor = verifier.issue_challenge("sess-02", "adult-portal.pl", t_now, &mut rng);
        assert!(
            WalletProver::prove_age_over_18(&minor_cred, &device_kp, &chal_minor, &mut rng)
                .is_err()
        );

        // 6. Test bezpieczeństwa: Unieważnienie poświadczenia w rejestrze Wystawcy -> ODRZUCONE
        issuer.revoke_credential(cred.credential_id);
        let verifier_updated = RelyingPartyVerifier::new(issuer.export_registry());
        let chal_rev =
            verifier_updated.issue_challenge("sess-03", "adult-portal.pl", t_now, &mut rng);
        assert!(WalletProver::prove_age_over_18(&cred, &device_kp, &chal_rev, &mut rng).is_err());
    }
}
