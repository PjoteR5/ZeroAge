use ark_ff::One;
use ark_std::rand::RngCore;
use serde::{Deserialize, Serialize};

use crate::date_witness::{CredentialDate, PublicAgeInputs};
use crate::issuer::SignedAgeCredential;
use crate::revocation::{NonceReplayCache, RevocationRegistry};
use crate::serialization::{
    ecdsa_sig, fp256_vec, hex32, ligero_openings, masked_transcript,
};
use zkp_circuits::age_circuit::build_age_and_validity_circuit;
use zkp_circuits::ecdsa_p256::{verify_ecdsa_message, EcdsaSignature, P256Point};
use zkp_core::field::Fp256;
use zkp_core::merkle::MerkleProof;
use zkp_core::protocol25::{
    MaskedTranscript, Protocol25Params, Protocol25Proof, Protocol25Prover, Protocol25Verifier,
};
use zkp_core::transcript::FiatShamirTranscript;

/// Bezpieczne parametry ZK-Ligero dla obwodu `is_over18` (długość rozszerzonego świadka = 187 elementów):
/// - `m = 13` wierszy (12 wierszy danych po `data_cols = 16` elementów = 192 miejsca + 1 wiersz maskujący),
/// - `k = 24` (`16` kolumn danych + `8` losowych kolumn maskujących w każdym wierszu dla pełnego ZK!),
/// - `n = 64` ($n \ge 2k - 1 = 47$, z czego otwieramy `open_t = 8` kolumn wyłącznie z przedziału `[24, 64)`!).
const MVP_LIGERO_M: usize = 13;
const MVP_LIGERO_DATA_COLS: usize = 16;
const MVP_LIGERO_K: usize = 24;
const MVP_LIGERO_N: usize = 64;
const MVP_LIGERO_OPEN_T: usize = 8;

pub fn mvp_protocol25_params() -> Protocol25Params {
    Protocol25Params::new(
        MVP_LIGERO_M,
        MVP_LIGERO_DATA_COLS,
        MVP_LIGERO_K,
        MVP_LIGERO_N,
        MVP_LIGERO_OPEN_T,
    )
}

/// Pakiet dowodu ZKP pełnoletności (`is_over18 == true`) przesyłany do Weryfikatora w postaci JSON.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MvpAgeProof {
    pub credential_id: u64,
    pub issuer_id: String,
    pub valid_from: CredentialDate,
    pub valid_until: CredentialDate,
    #[serde(with = "ecdsa_sig")]
    pub issuer_signature: EcdsaSignature,
    pub public_inputs: PublicAgeInputs,
    #[serde(with = "hex32")]
    pub ligero_root: [u8; 32],
    #[serde(with = "masked_transcript")]
    pub masked_transcript: MaskedTranscript<Fp256>,
    #[serde(with = "fp256_vec")]
    pub ligero_lin_comb: Vec<Fp256>,
    #[serde(with = "fp256_vec")]
    pub dot_product_codeword: Vec<Fp256>,
    #[serde(with = "fp256_vec")]
    pub quad_check_codeword: Vec<Fp256>,
    #[serde(with = "ligero_openings")]
    pub ligero_openings: Vec<(usize, Vec<Fp256>, MerkleProof)>,
}

impl MvpAgeProof {
    /// Serializuje paczkę dowodu ZKP do czytelnego formatu JSON (`NIZK JSON Payload`).
    pub fn to_json_pretty(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| format!("Błąd serializacji dowodu ZKP do JSON: {e}"))
    }

    /// Odtwarza paczkę dowodu ZKP z tekstu JSON przesłanego od klienta.
    pub fn from_json_str(json: &str) -> Result<Self, String> {
        serde_json::from_str(json)
            .map_err(|e| format!("Błąd deserializacji dowodu ZKP z JSON: {e}"))
    }
}

/// Generuje dowód ZKP potwierdzający, że w certyfikacie podpisanym przez Wystawcę flaga `is_over18 == true`.
pub fn generate_mvp_age_proof<R: RngCore>(
    credential: &SignedAgeCredential,
    verification_date: CredentialDate,
    challenge_nonce: [u8; 16],
    rng: &mut R,
) -> Result<MvpAgeProof, &'static str> {
    if !credential.verify_issuer_signature() {
        return Err("Nieprawidłowy podpis ECDSA P-256 Wystawcy na poświadczeniu");
    }

    let (public_inputs, private_witness) =
        credential.into_public_and_private_inputs(verification_date, challenge_nonce);

    if !private_witness.matches_commitment(&public_inputs.is_over18_commitment) {
        return Err("Prywatny świadek (is_over18, secret_salt) nie otwiera zobowiązania is_over18_commitment");
    }

    let circuit = build_age_and_validity_circuit::<Fp256>();
    let layer = &circuit.layers[0];
    let witness_wires = private_witness.synthesize_circuit_witness(&public_inputs);

    // Jawne więzy publicznych przewodów wejściowych (blokują podstawienie fałszywych dat lub stałej wire 0)
    let bound_public_wires = [
        (0usize, Fp256::one()),
        (1usize, Fp256::from(public_inputs.t_now_seconds())),
        (2usize, public_inputs.is_over18_commitment.to_field_element()),
        (4usize, credential.valid_from.to_field_element()),
        (5usize, credential.valid_until.to_field_element()),
    ];

    let params = mvp_protocol25_params();
    let mut transcript = init_mvp_transcript(&public_inputs, &credential.valid_from, &credential.valid_until);
    let p25_proof = Protocol25Prover::prove(
        layer,
        &witness_wires,
        &bound_public_wires,
        &params,
        &mut transcript,
        rng,
    )?;

    Ok(MvpAgeProof {
        credential_id: credential.credential_id,
        issuer_id: credential.issuer_id.clone(),
        valid_from: credential.valid_from,
        valid_until: credential.valid_until,
        issuer_signature: credential.issuer_signature,
        public_inputs,
        ligero_root: p25_proof.ligero_root,
        masked_transcript: p25_proof.masked_transcript,
        ligero_lin_comb: p25_proof.ligero_lin_comb,
        dot_product_codeword: p25_proof.dot_product_codeword,
        quad_check_codeword: p25_proof.quad_check_codeword,
        ligero_openings: p25_proof.ligero_openings,
    })
}

/// Weryfikuje po stronie Weryfikatora podpis Wystawcy na certyfikacie oraz nieinteraktywny dowód ZKP (`is_over18 == true`).
pub fn verify_mvp_age_proof(
    proof: &MvpAgeProof,
    trusted_issuer_pk: &P256Point,
) -> Result<(), &'static str> {
    if &proof.public_inputs.issuer_public_key != trusted_issuer_pk {
        return Err("Klucz publiczny Wystawcy w dowodzie nie zgadza się z kluczem zaufanym");
    }

    // 1. Weryfikacja podpisu ECDSA P-256 Wystawcy nad zobowiązaniem is_over18_commitment
    let signing_payload = SignedAgeCredential::canonical_signing_payload(
        proof.credential_id,
        &proof.issuer_id,
        &proof.public_inputs.is_over18_commitment,
        &proof.valid_from,
        &proof.valid_until,
    );
    if !verify_ecdsa_message(trusted_issuer_pk, &signing_payload, &proof.issuer_signature) {
        return Err("Podpis ECDSA P-256 Wystawcy na zobowiązaniu jest nieprawidłowy");
    }

    // 2. Weryfikacja dowodu NIZK Protokołu 2.5 (Sumcheck + Ligero + więzy liniowe i kwadratowe)
    let circuit = build_age_and_validity_circuit::<Fp256>();
    let layer = &circuit.layers[0];
    let bound_public_wires = [
        (0usize, Fp256::one()),
        (1usize, Fp256::from(proof.public_inputs.t_now_seconds())),
        (2usize, proof.public_inputs.is_over18_commitment.to_field_element()),
        (4usize, proof.valid_from.to_field_element()),
        (5usize, proof.valid_until.to_field_element()),
    ];

    let params = mvp_protocol25_params();
    let mut transcript = init_mvp_transcript(&proof.public_inputs, &proof.valid_from, &proof.valid_until);
    let p25_proof = Protocol25Proof {
        ligero_root: proof.ligero_root,
        masked_transcript: proof.masked_transcript.clone(),
        ligero_lin_comb: proof.ligero_lin_comb.clone(),
        dot_product_codeword: proof.dot_product_codeword.clone(),
        quad_check_codeword: proof.quad_check_codeword.clone(),
        ligero_openings: proof.ligero_openings.clone(),
    };

    Protocol25Verifier::verify(
        layer,
        &bound_public_wires,
        &params,
        &p25_proof,
        &mut transcript,
    )
}

/// Pełna weryfikacja po stronie Bramki Weryfikatora obejmująca:
/// 1. Sprawdzenie Rejestru Unieważnień Wystawcy (`RevocationRegistry`),
/// 2. Kontrolę świeżości jednorazowego wyzwania sesyjnego (`NonceReplayCache` — ochrona przed Replay Attack),
/// 3. Weryfikację podpisu ECDSA P-256 Wystawcy oraz dowodu matematycznego ZKP Protokołu 2.5,
/// 4. Oznaczenie wyzwania `challenge_nonce` jako zużytego po pozytywnej weryfikacji.
pub fn verify_mvp_age_proof_full(
    proof: &MvpAgeProof,
    trusted_issuer_pk: &P256Point,
    revocation_registry: &RevocationRegistry,
    replay_cache: &mut NonceReplayCache,
) -> Result<(), &'static str> {
    if revocation_registry.is_revoked(proof.credential_id) {
        return Err("Certyfikat został unieważniony w rejestrze Wystawcy");
    }

    if replay_cache.is_nonce_used(&proof.public_inputs.challenge_nonce) {
        return Err("Wykryto atak powtórzeniowy (Replay Attack): challenge_nonce został już zużyty");
    }

    verify_mvp_age_proof(proof, trusted_issuer_pk)?;

    replay_cache.mark_nonce_used(proof.public_inputs.challenge_nonce);
    Ok(())
}

fn init_mvp_transcript(
    public_inputs: &PublicAgeInputs,
    valid_from: &CredentialDate,
    valid_until: &CredentialDate,
) -> FiatShamirTranscript {
    let mut t = FiatShamirTranscript::new(b"ZeroAge-MVP-IsOver18-v2");
    t.append_message(
        b"verification_date",
        &public_inputs.t_now_seconds().to_be_bytes(),
    );
    t.append_message(
        b"valid_from",
        &valid_from.to_timestamp_seconds().to_be_bytes(),
    );
    t.append_message(
        b"valid_until",
        &valid_until.to_timestamp_seconds().to_be_bytes(),
    );
    t.append_root(b"is_over18_commitment", &public_inputs.is_over18_commitment.digest);
    t.append_field_element(b"issuer_pk_x", &public_inputs.issuer_public_key.x);
    t.append_field_element(b"issuer_pk_y", &public_inputs.issuer_public_key.y);
    t.append_message(b"challenge_nonce", &public_inputs.challenge_nonce);
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuer::CredentialIssuer;
    use ark_std::test_rng;

    #[test]
    fn test_mvp_flow_valid_adult_and_underage_rejection() {
        let mut rng = test_rng();
        let mut issuer = CredentialIssuer::new("Urząd-MVP", b"issuer-mvp-seed");

        let valid_from = CredentialDate::parse_iso("2026-01-01").unwrap();
        let valid_until = CredentialDate::parse_iso("2027-01-01").unwrap();
        let verify_date = CredentialDate::parse_iso("2026-11-17").unwrap();

        // 1. Obywatel pełnoletni (ur. 2004-05-15 -> is_over18 = true)
        let adult_dob = CredentialDate::parse_iso("2004-05-15").unwrap();
        let adult_cred = issuer
            .issue_age_credential("Jan Kowalski", adult_dob, valid_from, valid_until)
            .unwrap();
        assert!(adult_cred.private_witness.is_over18);

        let proof =
            generate_mvp_age_proof(&adult_cred, verify_date, [0xAAu8; 16], &mut rng).unwrap();
        assert!(verify_mvp_age_proof(&proof, &issuer.public_key()).is_ok());

        // 2. Sprawdzenie, że żadna otwarta kolumna Ligero nie pochodzi z części systematycznej [0, k)
        for (col_idx, _, _) in &proof.ligero_openings {
            assert!(
                *col_idx >= MVP_LIGERO_K,
                "Wyciek ZK: otwarto kolumnę systematyczną {} < {}",
                col_idx,
                MVP_LIGERO_K
            );
        }

        // 3. Test odporności na sfałszowanie transkryptu lub wielomianu iloczynu skalarnego
        let mut forged_proof = proof.clone();
        forged_proof.dot_product_codeword[0] += Fp256::one();
        assert!(
            verify_mvp_age_proof(&forged_proof, &issuer.public_key()).is_err(),
            "Sfałszowany wielomian ograniczeń Protokołu 2.5 musi zostać odrzucony!"
        );

        // 4. Obywatel niepełnoletni (ur. 2010-08-20 -> is_over18 = false) -> odrzucony
        let minor_dob = CredentialDate::parse_iso("2010-08-20").unwrap();
        let minor_cred = issuer
            .issue_age_credential("Niepełnoletni", minor_dob, valid_from, valid_until)
            .unwrap();
        assert!(!minor_cred.private_witness.is_over18);
        assert!(
            generate_mvp_age_proof(&minor_cred, verify_date, [0xBBu8; 16], &mut rng).is_err()
        );

        // 5. Serializacja do JSON + pełna weryfikacja (Replay Cache + Rejestr Unieważnień)
        let cred_json = adult_cred.to_json_pretty().unwrap();
        let restored_cred = SignedAgeCredential::from_json_str(&cred_json).unwrap();
        assert_eq!(adult_cred, restored_cred);

        let proof_json = proof.to_json_pretty().unwrap();
        let restored_proof = MvpAgeProof::from_json_str(&proof_json).unwrap();
        assert_eq!(proof, restored_proof);

        let mut replay_cache = NonceReplayCache::new();
        assert!(verify_mvp_age_proof_full(
            &restored_proof,
            &issuer.public_key(),
            &issuer.revocation_registry,
            &mut replay_cache,
        )
        .is_ok());

        // Ponowne wysłanie tego samego proof.json (Replay Attack) musi zostać zablokowane
        assert!(verify_mvp_age_proof_full(
            &restored_proof,
            &issuer.public_key(),
            &issuer.revocation_registry,
            &mut replay_cache,
        )
        .is_err());

        // Nowy dowód z unieważnionego certyfikatu musi zostać odrzucony
        issuer.revoke_credential(adult_cred.credential_id, verify_date, "Zgłoszona utrata");
        let fresh_proof =
            generate_mvp_age_proof(&adult_cred, verify_date, [0xCCu8; 16], &mut rng).unwrap();
        assert!(verify_mvp_age_proof_full(
            &fresh_proof,
            &issuer.public_key(),
            &issuer.revocation_registry,
            &mut replay_cache,
        )
        .is_err());
    }
}
