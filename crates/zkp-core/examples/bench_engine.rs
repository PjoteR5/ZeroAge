#![allow(non_local_definitions)]
#![allow(dead_code)]

use std::time::{Duration, Instant};
use ark_ff::{Fp256 as ArkFp256, Fp64, MontBackend, MontConfig, One, Zero};
use ark_std::test_rng;

use zkp_core::circuit::gate::{QuadGate, QuadTerm};
use zkp_core::circuit::layered::{build_eq_table, eq_eval, CircuitLayer};
use zkp_core::ligero::prover::LigeroProver;
use zkp_core::ligero::verifier::LigeroVerifier;
use zkp_core::protocol25::constraints::Protocol25Constraints;
use zkp_core::protocol25::pad::{LayerPads, MaskedRoundPoly, MaskedTranscript};
use zkp_core::sumcheck::prover::SumcheckProver;
use zkp_core::sumcheck::verifier::SumcheckVerifier;
use zkp_core::transcript::FiatShamirTranscript;

// Ciało 64-bitowe dla szybkich testów porównawczych
#[derive(MontConfig)]
#[modulus = "18446744069414584321"] // 2^64 - 2^32 + 1 (Goldilocks 64-bit prime)
#[generator = "7"]
pub struct Fq64Config;
pub type F64 = Fp64<MontBackend<Fq64Config, 1>>;

// Ciało NIST P-256 (256-bit prime) - dokładnie to samo co w artykule dla ECDSA!
#[derive(MontConfig)]
#[modulus = "115792089210356248762697446949407573530086143415290314195533631308867097853951"]
#[generator = "3"]
pub struct P256BaseConfig;
pub type Fp256 = ArkFp256<MontBackend<P256BaseConfig, 4>>;

pub struct BenchStats {
    pub min: Duration,
    pub max: Duration,
    pub avg: Duration,
    pub median: Duration,
    pub iterations: usize,
}

impl BenchStats {
    pub fn compute(mut samples: Vec<Duration>) -> Self {
        assert!(!samples.is_empty());
        samples.sort();
        let min = samples[0];
        let max = *samples.last().unwrap();
        let total: Duration = samples.iter().sum();
        let avg = total / (samples.len() as u32);
        let median = samples[samples.len() / 2];
        Self {
            min,
            max,
            avg,
            median,
            iterations: samples.len(),
        }
    }
}

pub fn format_duration(d: Duration) -> String {
    let nanos = d.as_nanos();
    if nanos < 1_000 {
        format!("{:>6} ns", nanos)
    } else if nanos < 1_000_000 {
        format!("{:>6.2} µs", nanos as f64 / 1_000.0)
    } else if nanos < 1_000_000_000 {
        format!("{:>6.2} ms", nanos as f64 / 1_000_000.0)
    } else {
        format!("{:>6.3} s ", nanos as f64 / 1_000_000_000.0)
    }
}

pub fn format_bytes(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

// ============================================================================
// 1. STRESS TEST BRAMEK (Gate Scaling: do 25 000 bramek w warstwie)
// ============================================================================
fn bench_gate_scaling(iterations: usize) {
    println!("\n┌────────────────────────────────────────────────────────────────────────┐");
    println!("│ 1. SKALOWANIE LICZBY BRAMEK W WARSTWIE (Gate Count Stress Test)        │");
    println!("├───────────┬──────────────┬──────────────┬──────────────┬───────────────┤");
    println!("│ Bramki    │ Forward-Pass │ Sumcheck P   │ Sumcheck V   │ Przepustowość │");
    println!("├───────────┼──────────────┼──────────────┼──────────────┼───────────────┤");

    let gate_counts = vec![100, 500, 2_000, 5_000, 10_000, 25_000];
    let in_width = 8;
    let omega_in = 3;
    let num_rounds = 2 * omega_in;

    for count in gate_counts {
        let out_width = count + 1;
        let mut gates = Vec::with_capacity(count);
        for i in 1..=count {
            let left = ((i * 3) % (in_width - 1)) + 1;
            let right = ((i * 5) % (in_width - 1)) + 1;
            gates.push(QuadGate::new(
                i,
                vec![
                    QuadTerm::mul(left, right),
                    QuadTerm::linear(left, F64::from(3u64)),
                ],
            ));
        }
        let layer = CircuitLayer::<F64>::new(0, in_width, out_width, gates);

        let mut witness = vec![F64::one()];
        for i in 1..in_width {
            witness.push(F64::from((i * 13 + 7) as u64));
        }

        let mut fwd_samples = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let start = Instant::now();
            let _out = layer.evaluate(&witness);
            fwd_samples.push(start.elapsed());
        }
        let fwd_stats = BenchStats::compute(fwd_samples);

        let omega_out = out_width.next_power_of_two().trailing_zeros() as usize;
        let r_out: Vec<F64> = (0..omega_out).map(|i| F64::from((i + 3) as u64)).collect();
        let alpha = F64::from(1u64);

        let mut prover_samples = Vec::with_capacity(iterations);
        let mut last_polys = Vec::new();
        let mut last_chals = Vec::new();

        for _ in 0..iterations {
            let start = Instant::now();
            let mut sc_prover = SumcheckProver::new(layer.clone(), alpha, r_out.clone(), r_out.clone(), &witness);
            last_polys.clear();
            last_chals.clear();
            for r in 0..num_rounds {
                let poly = sc_prover.compute_round_poly();
                let chal = F64::from((r + 29) as u64);
                last_polys.push(poly);
                last_chals.push(chal);
                sc_prover.receive_challenge(chal);
            }
            prover_samples.push(start.elapsed());
        }
        let prover_stats = BenchStats::compute(prover_samples);

        let v_out = layer.evaluate(&witness);
        let claim_0: F64 = (0..out_width).map(|i| eq_eval(&r_out, i) * v_out[i]).sum();
        let mut verifier_samples = Vec::with_capacity(iterations);

        for _ in 0..iterations {
            let start = Instant::now();
            let mut sc_verifier = SumcheckVerifier::new(layer.clone(), alpha, r_out.clone(), r_out.clone(), claim_0, claim_0);
            for (p, c) in last_polys.iter().zip(last_chals.iter()) {
                assert!(sc_verifier.verify_round(p, *c));
            }
            verifier_samples.push(start.elapsed());
        }
        let verifier_stats = BenchStats::compute(verifier_samples);

        let gates_per_sec = (count as f64) / prover_stats.avg.as_secs_f64();
        let throughput = if gates_per_sec > 1_000_000.0 {
            format!("{:.2} M bramek/s", gates_per_sec / 1_000_000.0)
        } else {
            format!("{:.1} k bramek/s", gates_per_sec / 1_000.0)
        };

        println!(
            "│ {:>7}   │ {} │ {} │ {} │ {:>13} │",
            count,
            format_duration(fwd_stats.avg),
            format_duration(prover_stats.avg),
            format_duration(verifier_stats.avg),
            throughput
        );
    }
    println!("└───────────┴──────────────┴──────────────┴──────────────┴───────────────┘");
}

// ============================================================================
// 2. STRESS TEST ŚWIADKA I LIGERO (Witness Size: do 4 096 elementów)
// ============================================================================
fn bench_witness_and_ligero_stress(iterations: usize) {
    println!("\n┌────────────────────────────────────────────────────────────────────────┐");
    println!("│ 2. SKALOWANIE ŚWIADKA W LIGERO IOP (Witness Size Stress Test)          │");
    println!("├───────────┬──────────────┬──────────────┬──────────────┬───────────────┤");
    println!("│ Świadek |w│ Macierz (mxk)│ Commit (RS+M)│ Otwarcie 64k │ Weryfikacja   │");
    println!("├───────────┼──────────────┼──────────────┼──────────────┼───────────────┤");

    let witness_sizes = vec![256, 512, 1024, 2048, 4096];

    for w_size in witness_sizes {
        let witness: Vec<F64> = (0..w_size).map(|i| F64::from((i * 3 + 1) as u64)).collect();

        let k = ((w_size as f64).sqrt().ceil() as usize).max(16);
        let m = (w_size + k - 1) / k;
        let n = k * 4;

        let query_count = 64.min(n);
        let query_cols: Vec<usize> = (0..query_count).map(|i| (i * (n / query_count)) % n).collect();
        let weights: Vec<F64> = (0..m).map(|i| F64::from((i + 5) as u64)).collect();

        let mut commit_samples = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let start = Instant::now();
            let prover = LigeroProver::<F64>::new(&witness, m, k, n);
            commit_samples.push(start.elapsed());
            assert_ne!(prover.commitment(), [0u8; 32]);
        }
        let commit_stats = BenchStats::compute(commit_samples);

        let prover = LigeroProver::<F64>::new(&witness, m, k, n);
        let root = prover.commitment();

        let mut open_samples = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let start = Instant::now();
            let _lin = prover.answer_linear_combination(&weights);
            let _cols = prover.open_columns(&query_cols);
            open_samples.push(start.elapsed());
        }
        let open_stats = BenchStats::compute(open_samples);

        let lin_resp = prover.answer_linear_combination(&weights);
        let openings = prover.open_columns(&query_cols);
        let verifier = LigeroVerifier::<F64>::new(m, k, n);

        let mut verify_samples = Vec::with_capacity(iterations);
        for _ in 0..iterations {
            let start = Instant::now();
            let ok1 = verifier.verify_openings(&root, &openings);
            let ok2 = verifier.verify_linear_combination(&lin_resp, &weights, &openings);
            verify_samples.push(start.elapsed());
            assert!(ok1 && ok2);
        }
        let verify_stats = BenchStats::compute(verify_samples);

        println!(
            "│ |w|={:>5} │ ({:>3} x {:>3}) │ {} │ {} │ {} │",
            w_size,
            m,
            k,
            format_duration(commit_stats.avg),
            format_duration(open_stats.avg),
            format_duration(verify_stats.avg)
        );
    }
    println!("└───────────┴──────────────┴──────────────┴──────────────┴───────────────┘");
}

// ============================================================================
// 3. PEŁNY TEST SKALI MDOC / ECDSA (Dokładne parametry z artykułu Frigo & shelat)
// Tabela 1: ECDSA (24,477 Quads, 1,038 Inputs, 22 rundy Sumchecka)
// Tabela 2: SHA-256 (66,760 Quads, 3,585 Inputs, 24 rundy Sumchecka)
// Tabela 12: Toy Credential (592,555 Quads, 20,171 Inputs, 30 rund Sumchecka)
// ============================================================================
fn bench_mdoc_full_scale(iterations: usize, quick: bool) {
    println!("\n┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐");
    println!("│ 3. PEŁNE SKALOWANIE DO POZIOMU MDOC / ECDSA (Parametry z artykułu Google 2025)                          │");
    println!("├───────────────────────┬───────────┬──────────────┬──────────────┬──────────────┬───────────────────────┤");
    println!("│ Poziom Poświadczenia  │ Quads / W │ Prover Total │ Verifier Tot │ Rozmiar Dow. │ Porównanie z Artykułem│");
    println!("├───────────────────────┼───────────┼──────────────┼──────────────┼──────────────┼───────────────────────┤");

    let configs: Vec<(&str, usize, usize, f64, f64, Option<f64>)> = if quick {
        vec![
            ("ECDSA P-256 (Tab. 1)", 24_477, 1_038, 29.0, 18.8, None),
            ("SHA-256 (1 blok, T.2)", 66_760, 3_585, 12.5, 6.13, None),
            ("mDoc Toy Credential", 150_000, 20_171, 290.0, 140.0, Some(291.0)),
        ]
    } else {
        vec![
            ("ECDSA P-256 (Tab. 1)", 24_477, 1_038, 29.0, 18.8, None),
            ("SHA-256 (1 blok, T.2)", 66_760, 3_585, 12.5, 6.13, None),
            ("mDoc Toy Credential", 592_555, 20_171, 290.0, 140.0, Some(291.0)),
        ]
    };

    let mut rng = test_rng();

    for (name, gate_count, in_width, paper_p_ms, _paper_v_ms, _paper_kb) in configs {
        let omega_in = in_width.next_power_of_two().trailing_zeros() as usize;
        let num_rounds = 2 * omega_in;
        let out_width = gate_count + 1;

        // Każda bramka ma unikalny przewód wyjściowy i, co odpowiada realnej strukturze warstwy
        let mut gates = Vec::with_capacity(gate_count);
        for i in 1..=gate_count {
            let left = ((i * 3) % (in_width - 1)) + 1;
            let right = ((i * 7) % (in_width - 1)) + 1;
            gates.push(QuadGate::new(
                i,
                vec![
                    QuadTerm::mul(left, right),
                    QuadTerm::linear(left, Fp256::from(3u64)),
                ],
            ));
        }
        let layer = CircuitLayer::<Fp256>::new(0, in_width, out_width, gates);

        let mut witness = vec![Fp256::one()];
        for i in 1..in_width {
            witness.push(Fp256::from((i * 10007 + 42) as u64));
        }
        let v_out = layer.evaluate(&witness);

        // Parametry Ligero: t = 132 otwarte kolumny wg strony 30 artykułu!
        let t_queries = 132;
        let mut prover_samples = Vec::with_capacity(iterations);
        let mut verifier_samples = Vec::with_capacity(iterations);
        let mut commit_ms_sum = 0.0;
        let mut sumcheck_ms_sum = 0.0;
        let mut open_ms_sum = 0.0;
        let mut proof_size_bytes = 0;

        for _ in 0..iterations {
            let start_p = Instant::now();

            // 1. One-Time Pad
            let pads = LayerPads::<Fp256>::sample(num_rounds, &mut rng);
            let mut w_prime = witness.clone();
            w_prime.extend(pads.to_vec());

            // 2. Ligero commit: macierz m x k
            let t_commit = Instant::now();
            let w_len = w_prime.len();
            let k = ((w_len as f64).sqrt().ceil() as usize).max(16);
            let m = (w_len + k - 1) / k;
            let n = k * 4; // stopa 1/4

            let mut padded_w = w_prime.clone();
            padded_w.resize(m * k, Fp256::zero());
            let ligero_prover = LigeroProver::<Fp256>::new(&padded_w, m, k, n);
            let commitment_root = ligero_prover.commitment();
            commit_ms_sum += t_commit.elapsed().as_secs_f64() * 1000.0;

            // 3. Transkrypt Fiat-Shamir
            let mut prover_transcript = FiatShamirTranscript::new(b"ZKP-MDOC-ISO-18013-5");
            prover_transcript.append_root(b"ligero_commitment", &commitment_root);

            let omega_out = out_width.next_power_of_two().trailing_zeros() as usize;
            let r_out: Vec<Fp256> = (0..omega_out).map(|i| Fp256::from((i + 5) as u64)).collect();
            let eq_out = build_eq_table(&r_out);
            let claim_y: Fp256 = v_out
                .iter()
                .zip(eq_out.iter())
                .map(|(v, e)| *v * *e)
                .sum();
            prover_transcript.append_field_element(b"initial_claim_y", &claim_y);

            let t_sumcheck = Instant::now();
            let alpha = Fp256::from(1u64);
            let mut sc_prover = SumcheckProver::new(layer.clone(), alpha, r_out.clone(), r_out.clone(), &witness);

            let mut masked_rounds = Vec::with_capacity(num_rounds);
            let mut challenges = Vec::with_capacity(num_rounds);

            // Wyliczamy rundy sumchecka szybkim algorytmem liniowym O(|Gates| + |V|)
            for round_idx in 0..num_rounds {
                let poly = sc_prover.compute_round_poly_fast();
                let masked_p = MaskedRoundPoly::mask([poly.eval_0, poly.eval_1, poly.eval_2], pads.round_pads[round_idx]);
                prover_transcript.append_field_elements(b"round_evals", &masked_p.as_array());
                let chal: Fp256 = prover_transcript.challenge_scalar(b"challenge_r");
                challenges.push(chal);
                sc_prover.receive_challenge(chal);
                masked_rounds.push(masked_p);
            }

            let (true_w_l, true_w_r) = sc_prover.compute_next_claims();
            sumcheck_ms_sum += t_sumcheck.elapsed().as_secs_f64() * 1000.0;

            let masked_w_l = true_w_l + pads.pad_l;
            let masked_w_r = true_w_r + pads.pad_r;
            prover_transcript.append_field_element(b"masked_w_l", &masked_w_l);
            prover_transcript.append_field_element(b"masked_w_r", &masked_w_r);

            let masked_transcript = MaskedTranscript {
                rounds: masked_rounds,
                masked_w_l,
                masked_w_r,
            };

            // 4. Zapytania Ligero (t=132 kolumny)
            let t_open = Instant::now();
            let linear_weights: Vec<Fp256> = prover_transcript.challenge_scalars(b"ligero_linear_weights", m);
            let linear_response = ligero_prover.answer_linear_combination(&linear_weights);
            let q_count = t_queries.min(n);
            let query_cols = prover_transcript.challenge_indices(b"ligero_query_cols", n, q_count);
            let column_proofs = ligero_prover.open_columns(&query_cols);
            open_ms_sum += t_open.elapsed().as_secs_f64() * 1000.0;

            let elapsed_p = start_p.elapsed();
            prover_samples.push(elapsed_p);

            if proof_size_bytes == 0 {
                let path_len = column_proofs[0].2.path.len();
                proof_size_bytes = 32 // Merkle root
                    + (num_rounds * 3 * 32) // Ewaluacje rund (32 bajty na Fp256)
                    + (2 * 32) // masked w_l, w_r
                    + (n * 32) // linear response
                    + q_count * (8 + (m * 32) + (path_len * 32)); // otwarte kolumny
            }

            // Verifier
            let start_v = Instant::now();
            let mut verifier_transcript = FiatShamirTranscript::new(b"ZKP-MDOC-ISO-18013-5");
            verifier_transcript.append_root(b"ligero_commitment", &commitment_root);
            verifier_transcript.append_field_element(b"initial_claim_y", &claim_y);

            let mut v_challenges = Vec::with_capacity(num_rounds);
            for round_idx in 0..num_rounds {
                verifier_transcript.append_field_elements(b"round_evals", &masked_transcript.rounds[round_idx].as_array());
                let v_chal: Fp256 = verifier_transcript.challenge_scalar(b"challenge_r");
                v_challenges.push(v_chal);
            }

            verifier_transcript.append_field_element(b"masked_w_l", &masked_transcript.masked_w_l);
            verifier_transcript.append_field_element(b"masked_w_r", &masked_transcript.masked_w_r);

            let v_linear_weights: Vec<Fp256> = verifier_transcript.challenge_scalars(b"ligero_linear_weights", m);
            let _v_query_cols = verifier_transcript.challenge_indices(b"ligero_query_cols", n, q_count);

            let ligero_verifier = LigeroVerifier::<Fp256>::new(m, k, n);
            let openings_ok = ligero_verifier.verify_openings(&commitment_root, &column_proofs);
            let lin_comb_ok = ligero_verifier.verify_linear_combination(&linear_response, &v_linear_weights, &column_proofs);
            assert!(openings_ok && lin_comb_ok);

            let q_eval = layer.eval_wiring_predicate(&r_out, &v_challenges[0..omega_in], &v_challenges[omega_in..2 * omega_in]);
            let constraints = Protocol25Constraints::<Fp256>::build(
                claim_y,
                &v_challenges,
                &masked_transcript,
                q_eval,
                witness.len(),
                omega_in,
            );
            assert!(constraints.verify_all(&w_prime));

            let elapsed_v = start_v.elapsed();
            verifier_samples.push(elapsed_v);
        }

        let p_stats = BenchStats::compute(prover_samples);
        let v_stats = BenchStats::compute(verifier_samples);
        let it_f = iterations as f64;

        let paper_str = format!("Art: {:.1} ms", paper_p_ms);
        println!(
            "│ {:<21} │ {:>5}k/{:>2}k │ {} │ {} │ {:>12} │ {:>21} │",
            name,
            gate_count / 1000,
            in_width / 1000,
            format_duration(p_stats.avg),
            format_duration(v_stats.avg),
            format_bytes(proof_size_bytes),
            paper_str
        );
        println!(
            "│   └─ fazy Provera     │ Commit: {:>6.2} ms │ Sumcheck: {:>6.2} ms │ Open: {:>6.2} ms               │",
            commit_ms_sum / it_f,
            sumcheck_ms_sum / it_f,
            open_ms_sum / it_f
        );
    }
    println!("└───────────────────────┴───────────┴──────────────┴──────────────┴──────────────┴───────────────────────┘");
}

fn main() {
    println!("╔═════════════════════════════════════════════════════════════════════════════════════════════╗");
    println!("║       KOMPLEKSOWY TEST WYDAJNOŚCIOWY DO POZIOMU MDOC (ISO 18013-5)                          ║");
    println!("║       Silnik ZeroAge: NIST P-256 + Sumcheck O(|G|) + Ligero (t=132) + OTP                   ║");
    println!("╚═════════════════════════════════════════════════════════════════════════════════════════════╝");

    let args: Vec<String> = std::env::args().collect();
    let quick = args.iter().any(|a| a == "--quick");
    let iters = if quick { 1 } else { 3 };

    println!("Tryb: {}", if quick { "Szybki profil (--quick)" } else { "Pełny benchmark (3 iteracje per próg)" });

    // 1. Skalowanie bramek (do 25k)
    bench_gate_scaling(iters);

    // 2. Skalowanie świadka w Ligero (do 4k)
    bench_witness_and_ligero_stress(iters);

    // 3. Pełny poziom mDoc: NIST P-256 (256-bit), 24k - 592k bramek, t=132 otwarte kolumny
    bench_mdoc_full_scale(iters, quick);

    println!("\n Test na poziomie mDoc zakończony sukcesem!");
}
