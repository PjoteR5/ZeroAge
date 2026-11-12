#![allow(non_local_definitions)]

use std::time::Instant;
use ark_ff::{Fp64, MontBackend, MontConfig, One, Zero};
use ark_std::test_rng;

use zkp_core::circuit::gate::QuadGate;
use zkp_core::circuit::layered::{eq_eval, CircuitLayer};
use zkp_core::ligero::prover::LigeroProver;
use zkp_core::ligero::verifier::LigeroVerifier;
use zkp_core::merkle::MerkleTree;
use zkp_core::protocol25::constraints::Protocol25Constraints;
use zkp_core::protocol25::pad::{LayerPads, MaskedRoundPoly, MaskedTranscript};
use zkp_core::rs_code::ReedSolomonEncoder;
use zkp_core::sumcheck::prover::SumcheckProver;
use zkp_core::transcript::FiatShamirTranscript;

#[derive(MontConfig)]
#[modulus = "18446744069414584321"]
#[generator = "7"]
pub struct Fq64Config;
pub type F64 = Fp64<MontBackend<Fq64Config, 1>>;

#[test]
fn test_perf_protocol25_scaling() {
    let mut rng = test_rng();
    let width = 8;
    let v_in = 3;
    let (m, k, n) = (6, 16, 32);

    let mut gates = Vec::new();
    for i in 1..width {
        gates.push(QuadGate::mul(i, i, (i % (width - 1)) + 1));
    }
    let layer = CircuitLayer::<F64>::new(0, width, width, gates);

    let mut witness = vec![F64::one()];
    for i in 1..width {
        witness.push(F64::from((i * 5 + 3) as u64));
    }
    let v_out = layer.evaluate(&witness);
    let num_rounds = 2 * v_in;

    let start_prover = Instant::now();

    // 1. Maski OTP
    let pads = LayerPads::<F64>::sample(num_rounds, &mut rng);
    let mut w_prime = witness.clone();
    w_prime.extend(pads.to_vec());

    // 2. Zaangażowanie Ligero
    let mut padded_w = w_prime.clone();
    padded_w.resize(m * k, F64::zero());
    let ligero_prover = LigeroProver::<F64>::new(&padded_w, m, k, n);
    let commitment_root = ligero_prover.commitment();

    // 3. Transkrypt Fiat-Shamir
    let mut prover_transcript = FiatShamirTranscript::new(b"ZKP-Bench-Protocol-2.5");
    prover_transcript.append_root(b"ligero_commitment", &commitment_root);

    let r_out: Vec<F64> = (0..v_in).map(|i| F64::from((i + 3) as u64)).collect();
    let claim_y: F64 = (0..width).map(|i| eq_eval(&r_out, i) * v_out[i]).sum();
    prover_transcript.append_field_element(b"initial_claim_y", &claim_y);

    let alpha = F64::from(1u64);
    let mut sc_prover = SumcheckProver::new(layer.clone(), alpha, r_out.clone(), r_out.clone(), &witness);

    let mut masked_rounds = Vec::with_capacity(num_rounds);
    let mut challenges = Vec::with_capacity(num_rounds);

    for round_idx in 0..num_rounds {
        let poly = sc_prover.compute_round_poly();
        let masked_p = MaskedRoundPoly::mask([poly.eval_0, poly.eval_1, poly.eval_2], pads.round_pads[round_idx]);
        prover_transcript.append_field_elements(b"round_evals", &masked_p.as_array());
        let chal: F64 = prover_transcript.challenge_scalar(b"challenge_r");
        challenges.push(chal);
        sc_prover.receive_challenge(chal);
        masked_rounds.push(masked_p);
    }

    let l_challenges = &challenges[0..v_in];
    let r_challenges = &challenges[v_in..2 * v_in];
    let true_w_l: F64 = (0..witness.len()).map(|i| eq_eval(l_challenges, i) * witness[i]).sum();
    let true_w_r: F64 = (0..witness.len()).map(|i| eq_eval(r_challenges, i) * witness[i]).sum();

    let masked_w_l = true_w_l + pads.pad_l;
    let masked_w_r = true_w_r + pads.pad_r;
    prover_transcript.append_field_element(b"masked_w_l", &masked_w_l);
    prover_transcript.append_field_element(b"masked_w_r", &masked_w_r);

    let masked_transcript = MaskedTranscript {
        rounds: masked_rounds,
        masked_w_l,
        masked_w_r,
    };

    let linear_weights: Vec<F64> = prover_transcript.challenge_scalars(b"ligero_linear_weights", m);
    let linear_response = ligero_prover.answer_linear_combination(&linear_weights);
    let query_count = 10.min(n);
    let query_cols = prover_transcript.challenge_indices(b"ligero_query_cols", n, query_count);
    let column_proofs = ligero_prover.open_columns(&query_cols);

    let prover_duration = start_prover.elapsed();

    // Weryfikacja
    let start_verifier = Instant::now();

    let mut verifier_transcript = FiatShamirTranscript::new(b"ZKP-Bench-Protocol-2.5");
    verifier_transcript.append_root(b"ligero_commitment", &commitment_root);
    verifier_transcript.append_field_element(b"initial_claim_y", &claim_y);

    let mut v_challenges = Vec::with_capacity(num_rounds);
    for round_idx in 0..num_rounds {
        verifier_transcript.append_field_elements(b"round_evals", &masked_transcript.rounds[round_idx].as_array());
        let v_chal: F64 = verifier_transcript.challenge_scalar(b"challenge_r");
        v_challenges.push(v_chal);
    }

    verifier_transcript.append_field_element(b"masked_w_l", &masked_transcript.masked_w_l);
    verifier_transcript.append_field_element(b"masked_w_r", &masked_transcript.masked_w_r);

    let v_linear_weights: Vec<F64> = verifier_transcript.challenge_scalars(b"ligero_linear_weights", m);
    let _v_query_cols = verifier_transcript.challenge_indices(b"ligero_query_cols", n, query_count);

    let ligero_verifier = LigeroVerifier::<F64>::new(m, k, n);
    let openings_ok = ligero_verifier.verify_openings(&commitment_root, &column_proofs);
    let lin_comb_ok = ligero_verifier.verify_linear_combination(&linear_response, &v_linear_weights, &column_proofs);
    assert!(openings_ok && lin_comb_ok);

    let q_eval = layer.eval_wiring_predicate(&r_out, &v_challenges[0..v_in], &v_challenges[v_in..2 * v_in]);
    let constraints = Protocol25Constraints::<F64>::build(
        claim_y,
        &v_challenges,
        &masked_transcript,
        q_eval,
        witness.len(),
        v_in,
    );
    assert!(constraints.verify_all(&w_prime));

    let verifier_duration = start_verifier.elapsed();

    println!(
        "\n[PERF RESULT] Protokół 2.5 (8 drutów, 6 rund sumchecka): Prover = {:?}, Verifier = {:?}",
        prover_duration, verifier_duration
    );
    assert!(verifier_duration < prover_duration);
}

#[test]
fn test_perf_reed_solomon_and_merkle() {
    let encoder = ReedSolomonEncoder::<F64>::new(64, 128);
    let msg: Vec<F64> = (0..64).map(|i| F64::from((i * 11 + 7) as u64)).collect();
    let start_rs = Instant::now();
    let codeword = encoder.encode(&msg);
    let rs_duration = start_rs.elapsed();
    assert_eq!(codeword.len(), 128);

    let raw_leaves: Vec<Vec<u8>> = (0..512)
        .map(|i| format!("leaf-{i}").into_bytes())
        .collect();
    let start_m = Instant::now();
    let tree = MerkleTree::from_data_slices(&raw_leaves);
    let m_duration = start_m.elapsed();
    assert_eq!(tree.num_leaves, 512);

    println!(
        "\n[PERF RESULT] RS Encode (64->128): {:?}, Merkle Tree (512 liści SHA-256): {:?}",
        rs_duration, m_duration
    );
}
