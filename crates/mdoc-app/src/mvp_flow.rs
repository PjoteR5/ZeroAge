use ark_ff::One;
use ark_std::rand::RngCore;

use crate::commitment::WitnessCommitment;
use crate::date_witness::{CredentialDate, PublicAgeInputs};
use crate::issuer::SignedAgeCredential;
use zkp_circuits::age_circuit::{
    build_age_and_validity_circuit, is_age_circuit_output_satisfied, AGE_CIRCUIT_IN_WIDTH,
    AGE_CIRCUIT_OUT_WIDTH,
};
use zkp_circuits::ecdsa_p256::{verify_ecdsa_message, EcdsaSignature, P256Point};
use zkp_core::circuit::layered::eq_eval;
use zkp_core::field::Fp256;
use zkp_core::merkle::MerkleProof;
use zkp_core::protocol25::constraints::Protocol25Constraints;
use zkp_core::protocol25::pad::{LayerPads, MaskedRoundPoly, MaskedTranscript};
use zkp_core::sumcheck::prover::SumcheckProver;
use zkp_core::transcript::FiatShamirTranscript;

const MVP_LIGERO_M: usize = 16;
const MVP_LIGERO_K: usize = 20;
const MVP_LIGERO_N: usize = 40;
const MVP_LIGERO_OPEN_T: usize = 8;

/// Minimalny pakiet dowodu ZKP w wersji MVP przesyłany do Weryfikatora.
/// Zawiera wyłącznie dane publiczne, podpis Wystawcy nad zobowiązaniem oraz zamaskowany dowód ZKP
/// (dokładna data urodzenia `birth_date` oraz sól `secret_salt` pozostają ukryte w portfelu).
#[derive(Clone, Debug)]
pub struct MvpAgeProof {
    pub credential_id: u64,
    pub issuer_id: String,
    pub valid_from: CredentialDate,
    pub valid_until: CredentialDate,
    pub issuer_signature: EcdsaSignature,
    pub public_inputs: PublicAgeInputs,
    pub ligero_root: [u8; 32],
    pub masked_transcript: MaskedTranscript<Fp256>,
    pub otp_quadratic_target: Fp256,
    pub ligero_lin_comb: Vec<Fp256>,
    pub ligero_openings: Vec<(usize, Vec<Fp256>, MerkleProof)>,
}

/// Generuje dowód ZKP pełnoletności ($\text{wiek} \ge 18$) na podstawie poświadczenia `SignedAgeCredential`.
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

    if !private_witness.matches_commitment(&public_inputs.dob_commitment) {
        return Err("Prywatny świadek (birth_date, secret_salt) nie otwiera zobowiązania dob_commitment");
    }

    // 1. Synteza wektora przewodów świadka (dane publiczne + ukryte + 64-bitowy rozkład różnic dat)
    let circuit = build_age_and_validity_circuit::<Fp256>();
    let layer = circuit.layers[0].clone();
    let witness_wires = private_witness.synthesize_circuit_witness(&public_inputs);

    let v_out = layer.evaluate(&witness_wires);
    if !is_age_circuit_output_satisfied(&v_out) {
        return Err("Obywatel nie spełnia warunku wiek >= 18 lub poświadczenie jest poza okresem ważności");
    }

    // 2. Maski One-Time Pad (Protokół 2.5) oraz zaangażowanie wektorowe Ligero
    let omega_in = AGE_CIRCUIT_IN_WIDTH.next_power_of_two().trailing_zeros() as usize;
    let num_rounds = 2 * omega_in;
    let pads = LayerPads::<Fp256>::sample(num_rounds, rng);

    let mut w_prime = witness_wires.clone();
    w_prime.extend(pads.to_vec());

    let witness_comm = WitnessCommitment::commit_witness(
        &w_prime,
        MVP_LIGERO_M,
        MVP_LIGERO_K,
        MVP_LIGERO_N,
        rng,
    );

    // 3. Transkrypt Fiata-Shamira i zamaskowany Sumcheck
    let mut transcript = init_mvp_transcript(&public_inputs, &witness_comm.root);
    let omega_out = AGE_CIRCUIT_OUT_WIDTH.next_power_of_two().trailing_zeros() as usize;
    let r_out: Vec<Fp256> = transcript.challenge_scalars(b"r_out", omega_out);
    let claim_y = eq_eval(&r_out, 0);
    transcript.append_field_element(b"claim_y", &claim_y);

    let mut sc_prover = SumcheckProver::new(
        layer.clone(),
        Fp256::one(),
        r_out.clone(),
        r_out.clone(),
        &witness_wires,
    );

    let mut rounds = Vec::with_capacity(num_rounds);
    let mut challenges = Vec::with_capacity(num_rounds);
    for r_idx in 0..num_rounds {
        let poly = sc_prover.compute_round_poly();
        let masked = MaskedRoundPoly::mask(
            [poly.eval_0, poly.eval_1, poly.eval_2],
            pads.round_pads[r_idx],
        );
        transcript.append_field_elements(b"round_poly", &masked.as_array());
        let ch: Fp256 = transcript.challenge_scalar(b"challenge_r");
        sc_prover.receive_challenge(ch);
        rounds.push(masked);
        challenges.push(ch);
    }

    let (w_l, w_r) = sc_prover.compute_next_claims();
    let masked_w_l = w_l + pads.pad_l;
    let masked_w_r = w_r + pads.pad_r;
    transcript.append_field_element(b"masked_w_l", &masked_w_l);
    transcript.append_field_element(b"masked_w_r", &masked_w_r);

    let masked_transcript = MaskedTranscript {
        rounds,
        masked_w_l,
        masked_w_r,
    };

    let q_eval = layer.eval_wiring_predicate(
        &r_out,
        &challenges[0..omega_in],
        &challenges[omega_in..2 * omega_in],
    );
    let constraints = Protocol25Constraints::build(
        claim_y,
        &challenges,
        &masked_transcript,
        q_eval,
        witness_wires.len(),
        omega_in,
    );
    debug_assert!(constraints.verify_all(&w_prime));

    // 4. Otwarcie losowych kolumn zaangażowania Ligero
    let mut row_weights: Vec<Fp256> =
        transcript.challenge_scalars(b"row_weights", MVP_LIGERO_M - 1);
    row_weights.push(Fp256::one());
    let queried_cols =
        transcript.challenge_indices(b"col_queries", MVP_LIGERO_N, MVP_LIGERO_OPEN_T);
    let (ligero_lin_comb, ligero_openings) =
        witness_comm.open_for_verifier(&row_weights, &queried_cols);

    Ok(MvpAgeProof {
        credential_id: credential.credential_id,
        issuer_id: credential.issuer_id.clone(),
        valid_from: credential.valid_from,
        valid_until: credential.valid_until,
        issuer_signature: credential.issuer_signature,
        public_inputs,
        ligero_root: witness_comm.root,
        masked_transcript,
        otp_quadratic_target: constraints.quad_constraint.target,
        ligero_lin_comb,
        ligero_openings,
    })
}

/// Weryfikuje po stronie Weryfikatora podpis Wystawcy na zobowiązaniu oraz nieinteraktywny dowód ZKP.
pub fn verify_mvp_age_proof(
    proof: &MvpAgeProof,
    trusted_issuer_pk: &P256Point,
) -> Result<(), &'static str> {
    if &proof.public_inputs.issuer_public_key != trusted_issuer_pk {
        return Err("Klucz publiczny Wystawcy w dowodzie nie zgadza się z kluczem zaufanym");
    }

    // 1. Weryfikacja podpisu ECDSA P-256 Wystawcy nad zobowiązaniem dob_commitment
    let signing_payload = SignedAgeCredential::canonical_signing_payload(
        proof.credential_id,
        &proof.issuer_id,
        &proof.public_inputs.dob_commitment,
        &proof.valid_from,
        &proof.valid_until,
    );
    if !verify_ecdsa_message(trusted_issuer_pk, &signing_payload, &proof.issuer_signature) {
        return Err("Podpis ECDSA P-256 Wystawcy na zobowiązaniu jest nieprawidłowy");
    }

    // 2. Odtworzenie wyzwań Fiata-Shamira i weryfikacja więzów obwodu wieku (Protokół 2.5)
    let circuit = build_age_and_validity_circuit::<Fp256>();
    let layer = circuit.layers[0].clone();
    let omega_in = AGE_CIRCUIT_IN_WIDTH.next_power_of_two().trailing_zeros() as usize;
    let num_rounds = 2 * omega_in;

    if proof.masked_transcript.rounds.len() != num_rounds {
        return Err("Nieprawidłowa liczba rund Sumchecka w dowodzie MVP");
    }

    let mut transcript = init_mvp_transcript(&proof.public_inputs, &proof.ligero_root);
    let omega_out = AGE_CIRCUIT_OUT_WIDTH.next_power_of_two().trailing_zeros() as usize;
    let r_out: Vec<Fp256> = transcript.challenge_scalars(b"r_out", omega_out);
    let claim_y = eq_eval(&r_out, 0);
    transcript.append_field_element(b"claim_y", &claim_y);

    let mut challenges = Vec::with_capacity(num_rounds);
    for masked in &proof.masked_transcript.rounds {
        transcript.append_field_elements(b"round_poly", &masked.as_array());
        let ch: Fp256 = transcript.challenge_scalar(b"challenge_r");
        challenges.push(ch);
    }

    transcript.append_field_element(b"masked_w_l", &proof.masked_transcript.masked_w_l);
    transcript.append_field_element(b"masked_w_r", &proof.masked_transcript.masked_w_r);

    let q_eval = layer.eval_wiring_predicate(
        &r_out,
        &challenges[0..omega_in],
        &challenges[omega_in..2 * omega_in],
    );
    let constraints = Protocol25Constraints::build(
        claim_y,
        &challenges,
        &proof.masked_transcript,
        q_eval,
        AGE_CIRCUIT_IN_WIDTH,
        omega_in,
    );
    if constraints.quad_constraint.target != proof.otp_quadratic_target {
        return Err("Weryfikacja ograniczenia kwadratowego Protokołu 2.5 nie powiodła się");
    }

    // 3. Weryfikacja otwarcia zaangażowania wektorowego Ligero (drzewo Merkle + kod RS)
    let mut row_weights: Vec<Fp256> =
        transcript.challenge_scalars(b"row_weights", MVP_LIGERO_M - 1);
    row_weights.push(Fp256::one());
    let expected_cols =
        transcript.challenge_indices(b"col_queries", MVP_LIGERO_N, MVP_LIGERO_OPEN_T);

    for ((idx, _, _), exp) in proof.ligero_openings.iter().zip(expected_cols.iter()) {
        if idx != exp {
            return Err("Niezgodność indeksów otwartych kolumn z wyzwaniami Fiata-Shamira");
        }
    }

    if !WitnessCommitment::verify_opening(
        &proof.ligero_root,
        MVP_LIGERO_M,
        MVP_LIGERO_K,
        MVP_LIGERO_N,
        &row_weights,
        &proof.ligero_lin_comb,
        &proof.ligero_openings,
    ) {
        return Err("Weryfikacja zobowiązania wektorowego Ligero nie powiodła się");
    }

    Ok(())
}

fn init_mvp_transcript(
    public_inputs: &PublicAgeInputs,
    ligero_root: &[u8; 32],
) -> FiatShamirTranscript {
    let mut t = FiatShamirTranscript::new(b"ZeroAge-MVP-AgeVerification-v1");
    t.append_message(
        b"verification_date",
        &public_inputs.t_now_seconds().to_be_bytes(),
    );
    t.append_message(b"min_age", &public_inputs.min_age_seconds.to_be_bytes());
    t.append_root(b"dob_commitment", &public_inputs.dob_commitment.digest);
    t.append_field_element(b"issuer_pk_x", &public_inputs.issuer_public_key.x);
    t.append_field_element(b"issuer_pk_y", &public_inputs.issuer_public_key.y);
    t.append_message(b"challenge_nonce", &public_inputs.challenge_nonce);
    t.append_root(b"ligero_root", ligero_root);
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

        // 1. Obywatel pełnoletni (ur. 2004-05-15 -> 22 lata)
        let adult_dob = CredentialDate::parse_iso("2004-05-15").unwrap();
        let adult_cred = issuer
            .issue_age_credential("Jan Kowalski", adult_dob, valid_from, valid_until)
            .unwrap();

        let proof =
            generate_mvp_age_proof(&adult_cred, verify_date, [0xAAu8; 16], &mut rng).unwrap();
        assert!(verify_mvp_age_proof(&proof, &issuer.public_key()).is_ok());

        // 2. Obywatel niepełnoletni (ur. 2010-08-20 -> 16 lat) -> odrzucony
        let minor_dob = CredentialDate::parse_iso("2010-08-20").unwrap();
        let minor_cred = issuer
            .issue_age_credential("Niepełnoletni", minor_dob, valid_from, valid_until)
            .unwrap();
        assert!(
            generate_mvp_age_proof(&minor_cred, verify_date, [0xBBu8; 16], &mut rng).is_err()
        );
    }
}
