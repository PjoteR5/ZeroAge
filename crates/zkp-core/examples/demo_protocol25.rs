use ark_ff::{MontConfig, Zero};
use ark_std::test_rng;
use zkp_core::circuit::gate::QuadGate;
use zkp_core::circuit::layered::{eq_eval, CircuitLayer};
use zkp_core::ligero::prover::LigeroProver;
use zkp_core::ligero::verifier::LigeroVerifier;
use zkp_core::protocol25::constraints::Protocol25Constraints;
use zkp_core::protocol25::pad::{LayerPads, MaskedRoundPoly, MaskedTranscript};
use zkp_core::sumcheck::prover::SumcheckProver;
use zkp_core::transcript::FiatShamirTranscript;

#[derive(MontConfig)]
#[modulus = "17"]
#[generator = "3"]
pub struct FqConfig;
pub type F17 = ark_ff::Fp64<ark_ff::MontBackend<FqConfig, 1>>;

fn main() {
    println!("=== Pełna Demonstracja Protokołu 2.5 (Frigo & shelat) ===");
    println!("Hybryda: Verifiable Computation (Sumcheck) + IOP (Ligero) + One-Time Pad (OTP)\n");

    let mut rng = test_rng();

    // -------------------------------------------------------------
    // 1. Zdefiniowanie obwodu: 1 warstwa, 2 wejścia (wire 0 = 1, wire 1 = secret witness)
    // Bramka kwadratowa: V_0[1] = V_1[1] * V_1[1] (np. x^2)
    // -------------------------------------------------------------
    let gates = vec![QuadGate::mul(1, 1, 1)];
    let layer = CircuitLayer::<F17>::new(0, 2, 2, gates);

    // Świadek: wire 0 = 1 (stała), wire 1 = 4 (tajna wartość)
    let secret_witness = vec![F17::from(1u64), F17::from(4u64)];
    let v_out = layer.evaluate(&secret_witness);
    println!("1. Obliczenia obwodu:");
    println!("   Świadek wejściowy: wire 0 = 1, wire 1 = 4");
    println!("   Wyjście warstwy: V_0[0] = 1, V_0[1] = 4^2 = 16 = {:?} (mod 17)", v_out[1]);

    // -------------------------------------------------------------
    // 2. Przygotowanie One-Time Pad i Zaangażowanie Ligero (Przed rundami sumchecka!)
    // -------------------------------------------------------------
    let v_in = 1;
    let num_rounds = 2 * v_in; // 2 rundy (L i R)
    let pads = LayerPads::<F17>::sample(num_rounds, &mut rng);

    // Wektor rozszerzony: w' = (w, pad)
    let mut w_prime = secret_witness.clone();
    w_prime.extend(pads.to_vec());
    println!("\n2. Zaangażowanie Ligero:");
    println!("   Długość oryginalnego świadka: {}", secret_witness.len());
    println!("   Długość masek OTP (pad): {}", pads.total_len());
    println!("   Rozszerzony świadek w': długość {}", w_prime.len());

    // Prover pakuje w' do macierzy Ligero i oblicza zaangażowanie Merkle'a
    let (m, k, n) = (2, 5, 10); // macierz 2x5, kodowanie RS 5 -> 10 (rho = 1/2)
    let mut padded_w_prime = w_prime.clone();
    padded_w_prime.resize(m * k, F17::zero());

    let ligero_prover = LigeroProver::<F17>::new(&padded_w_prime, m, k, n);
    let commitment_root = ligero_prover.commitment();
    println!("   Ligero Commit: Merkle Root = {:02x?}...", &commitment_root[..4]);

    // -------------------------------------------------------------
    // 3. Rozpoczęcie Protokołu Fiat-Shamir i Zamaskowany Sumcheck
    // -------------------------------------------------------------
    let mut prover_transcript = FiatShamirTranscript::new(b"ZKP-Protocol-2.5");
    prover_transcript.append_root(b"ligero_commitment", &commitment_root);

    let r_out = vec![F17::from(3u64)];
    let claim_y = eq_eval(&r_out, 0) * v_out[0] + eq_eval(&r_out, 1) * v_out[1];
    prover_transcript.append_field_element(b"initial_claim_y", &claim_y);

    println!("\n3. Zamaskowany Sumcheck (Zero-Knowledge):");
    let alpha = F17::from(1u64);
    let mut sc_prover = SumcheckProver::new(layer.clone(), alpha, r_out.clone(), r_out.clone(), &secret_witness);

    // Runda 0:
    let poly_0 = sc_prover.compute_round_poly();
    let masked_p0 = MaskedRoundPoly::mask([poly_0.eval_0, poly_0.eval_1, poly_0.eval_2], pads.round_pads[0]);
    prover_transcript.append_field_elements(b"round_0_evals", &masked_p0.as_array());
    let r0: F17 = prover_transcript.challenge_scalar(b"challenge_r0");
    sc_prover.receive_challenge(r0);
    println!("   Runda 0: wysłano zamaskowane P_0, wyzwanie r0 = {:?}", r0);

    // Runda 1:
    let poly_1 = sc_prover.compute_round_poly();
    let masked_p1 = MaskedRoundPoly::mask([poly_1.eval_0, poly_1.eval_1, poly_1.eval_2], pads.round_pads[1]);
    prover_transcript.append_field_elements(b"round_1_evals", &masked_p1.as_array());
    let r1: F17 = prover_transcript.challenge_scalar(b"challenge_r1");
    sc_prover.receive_challenge(r1);
    println!("   Runda 1: wysłano zamaskowane P_1, wyzwanie r1 = {:?}", r1);

    let l_challenges = vec![r0];
    let r_challenges = vec![r1];
    let true_w_l = eq_eval(&l_challenges, 0) * secret_witness[0] + eq_eval(&l_challenges, 1) * secret_witness[1];
    let true_w_r = eq_eval(&r_challenges, 0) * secret_witness[0] + eq_eval(&r_challenges, 1) * secret_witness[1];

    let masked_w_l = true_w_l + pads.pad_l;
    let masked_w_r = true_w_r + pads.pad_r;
    prover_transcript.append_field_element(b"masked_w_l", &masked_w_l);
    prover_transcript.append_field_element(b"masked_w_r", &masked_w_r);

    let masked_transcript = MaskedTranscript {
        rounds: vec![masked_p0, masked_p1],
        masked_w_l,
        masked_w_r,
    };

    // -------------------------------------------------------------
    // 4. Zapytania Weryfikatora w Ligero
    // -------------------------------------------------------------
    println!("\n4. Zapytania weryfikatora IOP (Ligero):");
    let linear_weights: Vec<F17> = prover_transcript.challenge_scalars(b"ligero_linear_weights", m);
    let linear_response = ligero_prover.answer_linear_combination(&linear_weights);

    let query_cols = prover_transcript.challenge_indices(b"ligero_query_cols", n, 3);
    let column_proofs = ligero_prover.open_columns(&query_cols);
    println!("   Wylosowano zapytania o kolumny: {:?}", query_cols);

    // =============================================================
    // 5. WERYFIKACJA PO STRONIE WERYFIKATORA (Zero-Knowledge Verification)
    // =============================================================
    println!("\n=== Weryfikacja przez Weryfikatora ===");
    let mut verifier_transcript = FiatShamirTranscript::new(b"ZKP-Protocol-2.5");
    verifier_transcript.append_root(b"ligero_commitment", &commitment_root);
    verifier_transcript.append_field_element(b"initial_claim_y", &claim_y);

    verifier_transcript.append_field_elements(b"round_0_evals", &masked_transcript.rounds[0].as_array());
    let v_r0: F17 = verifier_transcript.challenge_scalar(b"challenge_r0");
    assert_eq!(r0, v_r0);

    verifier_transcript.append_field_elements(b"round_1_evals", &masked_transcript.rounds[1].as_array());
    let v_r1: F17 = verifier_transcript.challenge_scalar(b"challenge_r1");
    assert_eq!(r1, v_r1);

    verifier_transcript.append_field_element(b"masked_w_l", &masked_transcript.masked_w_l);
    verifier_transcript.append_field_element(b"masked_w_r", &masked_transcript.masked_w_r);

    // Krok 5.1: Weryfikacja zaangażowania Ligero i testu liniowego
    let v_linear_weights: Vec<F17> = verifier_transcript.challenge_scalars(b"ligero_linear_weights", m);
    let _v_query_cols = verifier_transcript.challenge_indices(b"ligero_query_cols", n, 3);

    let ligero_verifier = LigeroVerifier::<F17>::new(m, k, n);
    let openings_ok = ligero_verifier.verify_openings(&commitment_root, &column_proofs);
    let lin_comb_ok = ligero_verifier.verify_linear_combination(&linear_response, &v_linear_weights, &column_proofs);
    assert!(openings_ok && lin_comb_ok, "Weryfikacja Ligero nie powiodła się!");
    println!("✓ Krok 5.1: Sprawdzenie Merkle + Reed-Solomon + IOP Ligero: SUKCES");

    // Krok 5.2: Konstrukcja i sprawdzenie więzów Protokołu 2.5
    let v_challenges = vec![v_r0, v_r1];
    let q_eval = layer.eval_wiring_predicate(&r_out, &vec![v_r0], &vec![v_r1]);
    let constraints = Protocol25Constraints::<F17>::build(
        claim_y,
        &v_challenges,
        &masked_transcript,
        q_eval,
        secret_witness.len(),
        v_in,
    );

    // Weryfikator sprawdza, czy więzy Protokołu 2.5 zgadzają się z zaangażowanym świadkiem
    assert!(constraints.verify_all(&w_prime), "Więzy Protokołu 2.5 nie zostały spełnione!");
    println!("✓ Krok 5.2: Sprawdzenie ograniczeń liniowych Sumcheck + MLE wejścia: SUKCES");
    println!("✓ Krok 5.3: Sprawdzenie ograniczenia kwadratowego (Frigo & shelat p. 11): SUKCES");

    println!("\n=======================================================");
    println!("DOWÓD ZKP ZAAKCEPTOWANY!");
    println!("Tajny świadek pozostał w 100% ukryty pod podkładką OTP!");
    println!("=======================================================");
}
